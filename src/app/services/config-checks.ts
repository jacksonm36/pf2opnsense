import { XMLParser, XMLValidator } from 'fast-xml-parser';
import { ARRAY_TAG_NAMES, asArray, asString } from '../mappings/xml-utils';
import { ConversionNotes, TARGET } from '../mappings/pfsense-to-opnsense';
import { CheckResult, summarizeChecks, ValidationReport } from './validation.types';

export interface ValidationContext {
  fileName: string;
  rawText: string;
  parsedInput?: any;
  mappedRoot?: { opnsense?: Record<string, unknown> };
  outputXml?: string;
  report?: ConversionNotes;
  convertError?: string;
}

function parser() {
  return new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: '@_',
    parseTagValue: false,
    parseAttributeValue: false,
    trimValues: true,
    isArray: (name: string) => ARRAY_TAG_NAMES.has(name),
    numberParseOptions: { hex: false, leadingZeros: true, skipLike: /.*/ },
  });
}

function pass(id: string, group: CheckResult['group'], title: string, detail: string): CheckResult {
  return { id, group, title, status: 'pass', detail };
}

function warn(id: string, group: CheckResult['group'], title: string, detail: string): CheckResult {
  return { id, group, title, status: 'warn', detail };
}

function fail(id: string, group: CheckResult['group'], title: string, detail: string): CheckResult {
  return { id, group, title, status: 'fail', detail };
}

function skip(id: string, group: CheckResult['group'], title: string, detail: string): CheckResult {
  return { id, group, title, status: 'skip', detail };
}

function hasKey(value: unknown, key: string): boolean {
  return !!value && typeof value === 'object' && key in (value as Record<string, unknown>);
}

export function parsePfSenseXml(rawText: string): { ok: true; parsed: any } | { ok: false; reason: string } {
  const trimmed = rawText.trim();
  if (!trimmed) {
    return { ok: false, reason: 'File is empty.' };
  }
  if (/BEGIN.*?config\.xml|-----BEGIN (PGP |AES |ENCRYPTED)/i.test(trimmed) && !trimmed.includes('<pfsense')) {
    return { ok: false, reason: 'This looks like an encrypted backup. Export an unencrypted config.xml from pfSense.' };
  }
  const valid = XMLValidator.validate(trimmed, { allowBooleanAttributes: true });
  if (valid !== true) {
    const err = valid as { err?: { msg?: string } };
    return { ok: false, reason: err?.err?.msg || 'File is not well-formed XML.' };
  }
  try {
    return { ok: true, parsed: parser().parse(trimmed) };
  } catch (error) {
    return { ok: false, reason: error instanceof Error ? error.message : 'XML parse failed.' };
  }
}

function checkInputXml(ctx: ValidationContext): CheckResult {
  const title = 'Well-formed XML';
  if (!ctx.rawText.trim()) {
    return fail('input-xml', 'input', title, 'The uploaded file is empty.');
  }
  if (/BEGIN.*?config\.xml|-----BEGIN (PGP |AES |ENCRYPTED)/i.test(ctx.rawText) && !ctx.rawText.includes('<pfsense')) {
    return fail('input-xml', 'input', title, 'Encrypted pfSense backup detected. Restore requires a plain config.xml.');
  }
  const valid = XMLValidator.validate(ctx.rawText.trim(), { allowBooleanAttributes: true });
  if (valid !== true) {
    const err = valid as { err?: { msg?: string; line?: number } };
    return fail('input-xml', 'input', title, err?.err?.msg || 'Not well-formed XML.');
  }
  return pass('input-xml', 'input', title, `${ctx.fileName || 'config.xml'} parsed as XML.`);
}

function checkPfSenseRoot(ctx: ValidationContext): CheckResult {
  const title = 'pfSense document';
  const pfsense = ctx.parsedInput?.pfsense;
  if (ctx.parsedInput?.opnsense && !pfsense) {
    return fail('input-root', 'input', title, 'This is already an OPNsense config. Upload a pfSense config.xml.');
  }
  if (!pfsense) {
    return fail('input-root', 'input', title, 'Missing <pfsense> root. This is not a pfSense configuration backup.');
  }
  return pass('input-root', 'input', title, 'Found a pfSense configuration document.');
}

function checkRevision(ctx: ValidationContext): CheckResult {
  const title = `pfSense ${TARGET.pfsenseRelease} revision`;
  const version = asString(ctx.parsedInput?.pfsense?.version);
  if (!version) {
    return warn('input-revision', 'input', title, `No <version> tag. Expected config revision ${TARGET.pfsenseConfigRevision} (pfSense ${TARGET.pfsenseRelease}).`);
  }
  if (version === TARGET.pfsenseConfigRevision) {
    return pass('input-revision', 'input', title, `Config revision ${version} matches pfSense ${TARGET.pfsenseRelease}.`);
  }
  return warn(
    'input-revision',
    'input',
    title,
    `Config revision is ${version}, not ${TARGET.pfsenseConfigRevision} (pfSense ${TARGET.pfsenseRelease}). Mapping still runs.`
  );
}

function checkSystem(ctx: ValidationContext): CheckResult {
  const title = 'System identity';
  const system = ctx.parsedInput?.pfsense?.system;
  const hostname = asString(system?.hostname);
  if (!hostname) {
    return fail('input-system', 'input', title, 'No system hostname. OPNsense restore needs a hostname.');
  }
  const users = asArray(system?.user);
  const detail = users.length
    ? `Hostname ${hostname}, ${users.length} local user(s).`
    : `Hostname ${hostname}. No local users besides what OPNsense will require as root.`;
  return pass('input-system', 'input', title, detail);
}

function checkInterfaces(ctx: ValidationContext): CheckResult {
  const title = 'Interface assignments';
  const interfaces = ctx.parsedInput?.pfsense?.interfaces || {};
  const names = Object.keys(interfaces).filter((name) => interfaces[name] && typeof interfaces[name] === 'object');
  if (!names.length) {
    return fail('input-interfaces', 'input', title, 'No interface assignments found.');
  }
  const withDevice = names.filter((name) => {
    const iface = Array.isArray(interfaces[name]) ? interfaces[name][0] : interfaces[name];
    return asString(iface?.if) || asString(iface?.ipaddr);
  });
  if (!withDevice.length) {
    return fail('input-interfaces', 'input', title, 'Interfaces exist but none have a device or address.');
  }
  return pass('input-interfaces', 'input', title, `Found ${names.join(', ')}.`);
}

function checkFilter(ctx: ValidationContext): CheckResult {
  const title = 'Firewall rules present';
  const filterRules = asArray(ctx.parsedInput?.pfsense?.filter?.rule);
  const toyRules = asArray(ctx.parsedInput?.pfsense?.firewall?.rule);
  const count = filterRules.length + toyRules.length;
  if (!count) {
    return warn('input-filter', 'input', title, 'No filter rules found. OPNsense will only get default-style mapped rules if any exist.');
  }
  return pass('input-filter', 'input', title, `${count} pfSense filter rule(s) will be mapped to OPNsense Firewall MVC.`);
}

function checkOpenVpnInput(ctx: ValidationContext): CheckResult {
  const title = 'OpenVPN source';
  const ovpn = ctx.parsedInput?.pfsense?.openvpn;
  const servers = asArray(ovpn?.['openvpn-server']).length;
  const clients = asArray(ovpn?.['openvpn-client']).length;
  const users = asArray(ovpn?.['openvpn-csc']).length;
  if (!servers && !clients && !users) {
    return skip('input-openvpn', 'input', title, 'No OpenVPN section in this backup.');
  }
  return pass(
    'input-openvpn',
    'input',
    title,
    `${servers} server(s), ${clients} client(s), ${users} client-specific user override(s) will be mapped to Instances.`
  );
}

function checkConvert(ctx: ValidationContext): CheckResult {
  const title = 'pfSense → OPNsense 26.7 map';
  if (ctx.convertError) {
    return fail('convert-map', 'convert', title, ctx.convertError);
  }
  if (!ctx.mappedRoot?.opnsense) {
    return fail('convert-map', 'convert', title, 'Mapper did not produce an OPNsense document.');
  }
  const stats = ctx.report?.stats;
  const summary = stats
    ? `${stats.filterRules} rules, ${stats.aliases} aliases, ${stats.openvpnServers} OpenVPN servers, ${stats.users} users.`
    : 'Mapper produced an OPNsense document.';
  return pass('convert-map', 'convert', title, summary);
}

function checkOutputXml(ctx: ValidationContext): CheckResult {
  const title = 'Generated XML is well-formed';
  if (!ctx.outputXml) {
    return fail('output-xml', 'output', title, 'No XML was generated.');
  }
  const valid = XMLValidator.validate(ctx.outputXml, { allowBooleanAttributes: true });
  if (valid !== true) {
    const err = valid as { err?: { msg?: string } };
    return fail('output-xml', 'output', title, err?.err?.msg || 'Generated XML is not well-formed.');
  }
  if (!ctx.outputXml.includes('<opnsense>')) {
    return fail('output-xml', 'output', title, 'Generated document is missing an <opnsense> root.');
  }
  if (ctx.outputXml.includes('<pfsense>')) {
    return fail('output-xml', 'output', title, 'Generated document still contains <pfsense>.');
  }
  return pass('output-xml', 'output', title, `Well-formed OPNsense XML (${ctx.outputXml.length} bytes).`);
}

function checkOutputSystem(ctx: ValidationContext): CheckResult {
  const title = 'OPNsense system / root account';
  const system = ctx.mappedRoot?.opnsense?.['system'] as any;
  const hostname = asString(system?.hostname);
  const users = asArray(system?.user);
  const root = users.find((user: any) => asString(user?.uid) === '0');
  if (!hostname) {
    return fail('output-system', 'output', title, 'Mapped config has no hostname.');
  }
  if (!root) {
    return fail('output-system', 'output', title, 'No uid 0 user. OPNsense restore requires root.');
  }
  if (asString(root.name) !== 'root') {
    return fail('output-system', 'output', title, `uid 0 is named "${asString(root.name)}"; OPNsense requires the name root.`);
  }
  return pass('output-system', 'output', title, `Hostname ${hostname}, uid 0 is root.`);
}

function checkOutputFirewallMvc(ctx: ValidationContext): CheckResult {
  const title = 'Firewall rules are MVC (26.7)';
  const opnsense = ctx.mappedRoot?.opnsense as any;
  const rules = asArray(opnsense?.OPNsense?.Firewall?.Filter?.rules?.rule);
  const legacy = opnsense?.filter;
  const legacyHasRules = legacy && typeof legacy === 'object' && asArray(legacy.rule).length > 0;
  if (legacyHasRules) {
    return fail('output-firewall', 'output', title, 'Legacy <filter><rule> is still populated. OPNsense 26.7 expects OPNsense/Firewall/Filter.');
  }
  if (!hasKey(opnsense, 'OPNsense') || !opnsense?.OPNsense?.Firewall?.Filter) {
    return fail('output-firewall', 'output', title, 'Missing OPNsense/Firewall/Filter MVC block.');
  }
  const inputCount = asArray(ctx.parsedInput?.pfsense?.filter?.rule).length + asArray(ctx.parsedInput?.pfsense?.firewall?.rule).length;
  if (inputCount && !rules.length) {
    return warn('output-firewall', 'output', title, 'Input had filter rules but none were mapped (they may have been match/separator rules).');
  }
  return pass('output-firewall', 'output', title, `${rules.length} rule(s) in OPNsense/Firewall/Filter. Legacy filter left empty.`);
}

function checkOutputAliases(ctx: ValidationContext): CheckResult {
  const title = 'Aliases are MVC';
  const inputAliases = asArray(ctx.parsedInput?.pfsense?.aliases?.alias);
  const outputAliases = asArray((ctx.mappedRoot?.opnsense as any)?.OPNsense?.Firewall?.Alias?.aliases?.alias);
  if (!inputAliases.length) {
    return skip('output-aliases', 'output', title, 'Source config has no aliases.');
  }
  if (!outputAliases.length) {
    return fail('output-aliases', 'output', title, 'Source aliases were not written to OPNsense/Firewall/Alias.');
  }
  const glued = outputAliases.some((alias: any) => {
    const content = asString(alias.content);
    return /[0-9]\d+\.\d+\.\d+\.\d+[0-9]/.test(content.replace(/\n/g, '')) && !content.includes('\n') && content.split('.').length > 4;
  });
  const hasNewline = outputAliases.some((alias: any) => asString(alias.content).includes('\n') || asString(alias.content).split(/\s+/).length <= 1);
  if (glued) {
    return fail('output-aliases', 'output', title, 'Alias addresses look concatenated without separators.');
  }
  return pass(
    'output-aliases',
    'output',
    title,
    `${outputAliases.length} alias(es) under OPNsense/Firewall/Alias` + (hasNewline ? ' with newline-separated content.' : '.')
  );
}

function checkOutputOpenVpn(ctx: ValidationContext): CheckResult {
  const title = 'OpenVPN Instances (not legacy)';
  const input = ctx.parsedInput?.pfsense?.openvpn;
  const hadOvpn =
    asArray(input?.['openvpn-server']).length +
      asArray(input?.['openvpn-client']).length +
      asArray(input?.['openvpn-csc']).length >
    0;
  const output = ctx.mappedRoot?.opnsense as any;
  if (output?.openvpn && (output.openvpn['openvpn-server'] || output.openvpn['openvpn-csc'])) {
    return fail(
      'output-openvpn',
      'output',
      title,
      'Legacy <openvpn-server>/<openvpn-csc> is still in the output. OPNsense 26.7 uses VPN → OpenVPN → Instances.'
    );
  }
  if (!hadOvpn) {
    return skip('output-openvpn', 'output', title, 'No OpenVPN in the source config.');
  }
  const instances = asArray(output?.OPNsense?.OpenVPN?.Instances?.Instance);
  const overwrites = asArray(output?.OPNsense?.OpenVPN?.Overwrites?.Overwrite);
  if (!instances.length) {
    return fail('output-openvpn', 'output', title, 'Source OpenVPN was not mapped to OPNsense/OpenVPN/Instances.');
  }
  return pass(
    'output-openvpn',
    'output',
    title,
    `${instances.length} Instance(s), ${overwrites.length} user overwrite(s), under VPN → OpenVPN → Instances.`
  );
}

function checkOutputGateways(ctx: ValidationContext): CheckResult {
  const title = 'Gateways MVC';
  const inputItems = asArray(ctx.parsedInput?.pfsense?.gateways?.gateway_item);
  if (!inputItems.length) {
    return skip('output-gateways', 'output', title, 'No pfSense gateways to map.');
  }
  const items = asArray((ctx.mappedRoot?.opnsense as any)?.OPNsense?.Gateways?.gateway_item);
  if (!items.length) {
    return fail('output-gateways', 'output', title, 'Gateways were not written to OPNsense/Gateways.');
  }
  const overweight = items.filter((item: any) => parseInt(asString(item.weight), 10) > 10);
  if (overweight.length) {
    return fail('output-gateways', 'output', title, 'A gateway weight is still above 10 (OPNsense max).');
  }
  return pass('output-gateways', 'output', title, `${items.length} gateway(s) in OPNsense/Gateways with valid weights.`);
}

function checkOutputDhcp(ctx: ValidationContext): CheckResult {
  const title = 'DHCP → dnsmasq';
  const dhcpd = ctx.parsedInput?.pfsense?.dhcpd;
  const hadRange =
    !!dhcpd &&
    Object.values(dhcpd as Record<string, any>).some((cfg) => asString(cfg?.range?.from) && asString(cfg?.range?.to));
  if (!hadRange) {
    return skip('output-dhcp', 'output', title, 'No ISC dhcpd pools in the source config.');
  }
  const ranges = asArray((ctx.mappedRoot?.opnsense as any)?.dnsmasq?.dhcp_ranges);
  if (!ranges.length) {
    return fail('output-dhcp', 'output', title, 'dhcpd pools were not mapped to dnsmasq dhcp_ranges.');
  }
  return pass('output-dhcp', 'output', title, `${ranges.length} dnsmasq DHCP range(s) for OPNsense ${TARGET.opnsenseSeries}.`);
}

function looksLikePem(blob: string, marker: RegExp): boolean {
  const compact = blob.replace(/\s+/g, '');
  if (!compact) {
    return false;
  }
  try {
    const BufferCtor = (globalThis as { Buffer?: { from: (data: string, enc: string) => { toString: (enc: string) => string } } }).Buffer;
    const decoded = BufferCtor
      ? BufferCtor.from(compact, 'base64').toString('utf8')
      : typeof atob === 'function'
        ? atob(compact)
        : '';
    return marker.test(decoded);
  } catch {
    return false;
  }
}

function pkiItems(value: unknown): any[] {
  return asArray(value).filter((item) => item && typeof item === 'object');
}

function checkOutputTrust(ctx: ValidationContext): CheckResult {
  const title = 'Certificates and CAs';
  const inputCas = pkiItems(ctx.parsedInput?.pfsense?.ca);
  const inputCerts = pkiItems(ctx.parsedInput?.pfsense?.cert);
  if (!inputCas.length && !inputCerts.length) {
    return skip('output-trust', 'output', title, 'Source config has no CA or certificate entries.');
  }
  const output = ctx.mappedRoot?.opnsense as any;
  const outputCas = pkiItems(output?.ca);
  const outputCerts = pkiItems(output?.cert);
  if (inputCas.length && outputCas.length !== inputCas.length) {
    return fail('output-trust', 'output', title, `Source had ${inputCas.length} CA(s) but output has ${outputCas.length}.`);
  }
  if (inputCerts.length && outputCerts.length !== inputCerts.length) {
    return fail('output-trust', 'output', title, `Source had ${inputCerts.length} certificate(s) but output has ${outputCerts.length}.`);
  }
  const caIds = new Set(outputCas.map((ca: any) => asString(ca.refid)).filter(Boolean));
  const missingCrt = [...outputCas, ...outputCerts].filter((item: any) => !looksLikePem(asString(item.crt), /BEGIN CERTIFICATE/));
  if (missingCrt.length) {
    return fail(
      'output-trust',
      'output',
      title,
      `${missingCrt.length} CA/certificate blob(s) are missing a base64 PEM certificate.`
    );
  }
  const dangling = outputCerts.filter((cert: any) => {
    const caref = asString(cert.caref);
    return caref && !caIds.has(caref);
  });
  if (dangling.length) {
    return fail('output-trust', 'output', title, `${dangling.length} certificate(s) reference a CA that was not copied.`);
  }
  const weakKeys = outputCerts.filter((cert: any) => asString(cert.prv) && !looksLikePem(asString(cert.prv), /BEGIN .*PRIVATE KEY/));
  const userCerts = outputCerts.filter((cert: any) => asString(cert.type) === 'user').length;
  const detail = `${outputCas.length} CA(s), ${outputCerts.length} certificate(s)` +
    (userCerts ? `, ${userCerts} user cert(s)` : '') +
    ' copied with matching refids.';
  if (weakKeys.length) {
    return warn('output-trust', 'output', title, `${detail} ${weakKeys.length} private key(s) are not valid PEM — System → Trust after import.`);
  }
  return pass('output-trust', 'output', title, detail);
}

function ipsecHasTunnel(ipsec: any): boolean {
  if (!ipsec || typeof ipsec !== 'object') {
    return false;
  }
  const phase1 = asArray(ipsec.phase1).some((item: any) => !!asString(item?.['remote-gateway']));
  const phase2 = asArray(ipsec.phase2).some(
    (item: any) => !!asString(item?.localid?.address || item?.localid?.type) || !!asString(item?.remoteid?.address)
  );
  const mobile = asArray(ipsec.mobilekey).some(
    (item: any) => !!asString(item?.ident) && !!asString(item?.['pre-shared-key'])
  );
  return phase1 || phase2 || mobile;
}

function checkOutputIpsec(ctx: ValidationContext): CheckResult {
  const title = 'IPsec tunnels';
  const input = ctx.parsedInput?.pfsense?.ipsec;
  if (isEmptySection(input) || !ipsecHasTunnel(input)) {
    return skip('output-ipsec', 'output', title, 'No usable IPsec tunnels or mobile keys in the source config.');
  }
  const output = (ctx.mappedRoot?.opnsense as any)?.ipsec;
  if (!ipsecHasTunnel(output)) {
    return fail('output-ipsec', 'output', title, 'Source IPsec tunnels/keys were not copied to the OPNsense document.');
  }
  const p1 = asArray(output.phase1).length;
  const p2 = asArray(output.phase2).length;
  const keys = asArray(output.mobilekey).length;
  return warn(
    'output-ipsec',
    'output',
    title,
    `Copied ${p1} phase1, ${p2} phase2, ${keys} mobile key(s) in legacy form. OPNsense 26.7 uses VPN → IPsec → Connections; migrate after import.`
  );
}

function checkOutputPpps(ctx: ValidationContext): CheckResult {
  const title = 'PPP / PPPoE links';
  const inputLinks = asArray(ctx.parsedInput?.pfsense?.ppps?.ppp).filter((link: any) => asString(link?.type) || asString(link?.if) || asString(link?.ports));
  if (!inputLinks.length) {
    return skip('output-ppps', 'output', title, 'No PPP/PPPoE links in the source config.');
  }
  const outputLinks = asArray((ctx.mappedRoot?.opnsense as any)?.ppps?.ppp).filter((link: any) => asString(link?.type) || asString(link?.if) || asString(link?.ports));
  if (outputLinks.length !== inputLinks.length) {
    return fail('output-ppps', 'output', title, `Source had ${inputLinks.length} PPP link(s) but output has ${outputLinks.length}.`);
  }
  const incomplete = outputLinks.filter((link: any) => !asString(link.type) || !(asString(link.if) || asString(link.ports)));
  if (incomplete.length) {
    return fail('output-ppps', 'output', title, `${incomplete.length} PPP link(s) are missing type or interface.`);
  }
  return pass('output-ppps', 'output', title, `${outputLinks.length} PPP/PPPoE link(s) copied.`);
}

function checkOutputSyslog(ctx: ValidationContext): CheckResult {
  const title = 'Syslog';
  const input = ctx.parsedInput?.pfsense?.syslog;
  if (isEmptySection(input)) {
    return skip('output-syslog', 'output', title, 'No syslog section in the source config.');
  }
  const output = (ctx.mappedRoot?.opnsense as any)?.syslog;
  if (isEmptySection(output)) {
    return fail('output-syslog', 'output', title, 'Syslog settings were not copied.');
  }
  const nentries = asString(output.nentries) || asString(input.nentries);
  const remote = [output.remoteserver, output.remoteserver2, output.remoteserver3]
    .map(asString)
    .filter(Boolean);
  const inputRemote = [input.remoteserver, input.remoteserver2, input.remoteserver3].map(asString).filter(Boolean);
  if (inputRemote.length && remote.length !== inputRemote.length) {
    return fail('output-syslog', 'output', title, 'Remote syslog server(s) from the source were not copied.');
  }
  const detail = `nentries=${nentries || 'default'}` + (remote.length ? `, ${remote.length} remote server(s)` : ', local only');
  return pass('output-syslog', 'output', title, `Syslog copied (${detail}).`);
}

function checkOutputCron(ctx: ValidationContext): CheckResult {
  const title = 'Cron jobs';
  const inputItems = asArray(ctx.parsedInput?.pfsense?.cron?.item).filter((item: any) => asString(item?.command));
  if (!inputItems.length) {
    return skip('output-cron', 'output', title, 'No cron jobs in the source config.');
  }
  const outputItems = asArray((ctx.mappedRoot?.opnsense as any)?.cron?.item).filter((item: any) => asString(item?.command));
  if (outputItems.length !== inputItems.length) {
    return fail('output-cron', 'output', title, `Source had ${inputItems.length} cron job(s) but output has ${outputItems.length}.`);
  }
  const missingWho = outputItems.filter((item: any) => !asString(item.who));
  if (missingWho.length) {
    return fail('output-cron', 'output', title, `${missingWho.length} cron job(s) are missing a user.`);
  }
  const pfsenseOnly = outputItems.filter((item: any) =>
    /\/etc\/rc\.(update_bogons|dyndns|update_urltables)|\/usr\/local\/pkg\//.test(asString(item.command))
  );
  const detail = `${outputItems.length} cron job(s) copied.`;
  if (pfsenseOnly.length) {
    return warn(
      'output-cron',
      'output',
      title,
      `${detail} ${pfsenseOnly.length} job(s) call pfSense-only scripts and will not run on OPNsense.`
    );
  }
  return pass('output-cron', 'output', title, detail);
}

function checkOutputDynDns(ctx: ValidationContext): CheckResult {
  const title = 'DynDNS → os-ddclient';
  const inputAccounts = asArray(ctx.parsedInput?.pfsense?.dyndnses?.dyndns).filter(
    (row: any) => asString(row?.type) || asString(row?.host) || asString(row?.username)
  );
  if (!inputAccounts.length) {
    return skip('output-dyndns', 'output', title, 'No DynDNS accounts in the source config.');
  }
  const output = ctx.mappedRoot?.opnsense as any;
  if (output?.dyndnses) {
    return fail('output-dyndns', 'output', title, 'Legacy <dyndnses> was dumped. OPNsense 26.7 expects OPNsense/DynDNS (os-ddclient).');
  }
  const accounts = asArray(output?.OPNsense?.DynDNS?.accounts?.account);
  if (accounts.length !== inputAccounts.length) {
    return fail('output-dyndns', 'output', title, `Source had ${inputAccounts.length} DynDNS account(s) but output has ${accounts.length} under OPNsense/DynDNS.`);
  }
  const missingHost = accounts.filter((account: any) => !asString(account.hostnames));
  const detail = `${accounts.length} account(s) in OPNsense/DynDNS. Install os-ddclient.`;
  if (missingHost.length) {
    return warn('output-dyndns', 'output', title, `${detail} ${missingHost.length} account(s) have no hostname.`);
  }
  return pass('output-dyndns', 'output', title, detail);
}

function checkOutputOvpnWizard(ctx: ValidationContext): CheckResult {
  const title = 'OpenVPN wizard leftover';
  const hadWizard = !isEmptySection(ctx.parsedInput?.pfsense?.ovpnserver);
  const dumped = !isEmptySection((ctx.mappedRoot?.opnsense as any)?.ovpnserver);
  if (dumped) {
    return fail(
      'output-ovpnwizard',
      'output',
      title,
      'pfSense <ovpnserver> wizard state was copied. That is not a live OpenVPN config and is not used by OPNsense 26.7.'
    );
  }
  if (!hadWizard) {
    return skip('output-ovpnwizard', 'output', title, 'No pfSense OpenVPN wizard state in the source config.');
  }
  return pass(
    'output-ovpnwizard',
    'output',
    title,
    'pfSense OpenVPN wizard state was omitted. Live servers/clients were mapped to Instances.'
  );
}

function isEmptySection(value: unknown): boolean {
  if (value == null || value === '') {
    return true;
  }
  if (Array.isArray(value)) {
    return value.length === 0;
  }
  if (typeof value === 'object') {
    return Object.keys(value as object).length === 0;
  }
  return false;
}

export function runValidators(ctx: ValidationContext): ValidationReport {
  const checks: CheckResult[] = [
    checkInputXml(ctx),
    checkPfSenseRoot(ctx),
    checkRevision(ctx),
    checkSystem(ctx),
    checkInterfaces(ctx),
    checkFilter(ctx),
    checkOpenVpnInput(ctx),
    checkConvert(ctx),
    checkOutputXml(ctx),
    checkOutputSystem(ctx),
    checkOutputFirewallMvc(ctx),
    checkOutputAliases(ctx),
    checkOutputOpenVpn(ctx),
    checkOutputGateways(ctx),
    checkOutputDhcp(ctx),
    checkOutputTrust(ctx),
    checkOutputIpsec(ctx),
    checkOutputPpps(ctx),
    checkOutputSyslog(ctx),
    checkOutputCron(ctx),
    checkOutputDynDns(ctx),
    checkOutputOvpnWizard(ctx),
  ];

  const xmlFailed = checks.some((check) => check.id === 'input-xml' && check.status === 'fail');
  const rootFailed = checks.some((check) => check.id === 'input-root' && check.status === 'fail');
  const convertFailed = checks.some((check) => check.id === 'convert-map' && check.status === 'fail');

  const normalized = checks.map((check) => {
    if (xmlFailed && check.id !== 'input-xml') {
      return skip(check.id, check.group, check.title, 'Skipped because the file is not valid XML.');
    }
    if (rootFailed && check.id !== 'input-xml' && check.id !== 'input-root') {
      return skip(check.id, check.group, check.title, 'Skipped because this is not a pfSense config.');
    }
    if (convertFailed && check.group === 'output') {
      return skip(check.id, check.group, check.title, 'Skipped because conversion failed.');
    }
    return check;
  });

  return summarizeChecks(normalized);
}
