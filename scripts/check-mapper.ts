import { readFileSync } from 'node:fs';
import { XMLParser } from 'fast-xml-parser';
import { ARRAY_TAG_NAMES } from '../src/app/mappings/xml-utils';
import { mapPFtoOPN } from '../src/app/mappings/pfsense-to-opnsense';
import { ConverterService } from '../src/app/services/converter.service';

function parse(xml: string) {
  return new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: '@_',
    parseTagValue: false,
    parseAttributeValue: false,
    trimValues: true,
    isArray: (name: string) => ARRAY_TAG_NAMES.has(name),
    numberParseOptions: { hex: false, leadingZeros: true, skipLike: /.*/ },
  }).parse(xml);
}

function assert(condition: unknown, message: string) {
  if (!condition) {
    throw new Error(message);
  }
}

function asArraySafe(value: any) {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

function failSummary(label: string, checks: { id: string; status: string; detail: string }[]) {
  const failed = checks.filter((check) => check.status === 'fail');
  return `${label} should be downloadable. Failures: ${JSON.stringify(failed)}`;
}

async function main() {
  const xml = readFileSync('sample-files/pfsense-2.7.0.xml', 'utf8');
  const mapped = mapPFtoOPN(parse(xml));
  if (mapped instanceof Error) {
    throw mapped;
  }

  const root = mapped.root.opnsense as any;
  assert(root.system.hostname === 'edge', 'hostname');
  assert(root.system.user[0].name === 'root', 'uid 0 renamed to root');
  assert(root.interfaces.lan.ipaddr === '192.168.1.1', 'lan ip');
  assert(root.interfaces.wan.if === 'em0', 'wan if');
  assert(root.OPNsense.Firewall.Filter.rules.rule.length === 3, 'three MVC rules');
  assert(root.OPNsense.Firewall.Filter.rules.rule[0].source_net === 'lan', 'lan source');
  assert(root.OPNsense.Firewall.Alias.aliases.alias[0].content.includes('192.168.1.10'), 'alias content');
  assert(root.OPNsense.Firewall.Alias.aliases.alias[0].content.includes('\n'), 'alias newline separator');
  assert(root.dnsmasq.dhcp_ranges[0].start_addr === '192.168.1.100', 'dhcp range');
  assert(root.OPNsense.Gateways.gateway_item[0].weight === '1', 'gateway weight');
  assert(!root.installedpackages, '2.7.0 fixture has no packages');
  assert(root.filter && Object.keys(root.filter).length === 0, 'legacy filter empty');

  const complex = mapPFtoOPN(parse(readFileSync('sample-files/complex-pfsense.xml', 'utf8')));
  assert(!(complex instanceof Error), 'complex sample should convert');
  const complexRoot = (complex as Exclude<typeof complex, Error>).root.opnsense as any;
  const complexReport = (complex as Exclude<typeof complex, Error>).report;
  assert(!complexRoot.openvpn, 'legacy OpenVPN section must not be written');
  assert(complexRoot.OPNsense.OpenVPN.Instances.Instance.length === 2, 'OpenVPN Instances');
  assert(complexRoot.OPNsense.OpenVPN.Instances.Instance.some((i: any) => i.role === 'server' && i.server === '10.2.1.0/24'), 'tun tunnel mapped to Instance server');
  assert(complexRoot.OPNsense.OpenVPN.Instances.Instance.some((i: any) => i.vpnid === '2' && i.redirect_gateway === 'def1'), 'tun redirect gateway');
  assert(complexRoot.OPNsense.OpenVPN.Instances.Instance.some((i: any) => i.vpnid === '1' && !i.redirect_gateway), 'tap without empty gwredir');
  assert(complexRoot.OPNsense.OpenVPN.StaticKeys.StaticKey.length >= 1, 'TLS static keys');
  assert(complexRoot.OPNsense.OpenVPN.Overwrites.Overwrite.length === 3, 'MVC OpenVPN user overwrites');
  assert(complexRoot.OPNsense.OpenVPN.Overwrites.Overwrite.some((u: any) => u.common_name === 'Lolercoaster'), 'CSC common name');
  assert(complexRoot.installedpackages, 'packages copied');
  assert(complexReport.stats.openvpnUsers === 3, 'openvpn user stats');
  assert(complexReport.stats.packages > 0, 'package stats');
  assert(asArraySafe(complexRoot.cert).some((c: any) => c.type === 'user'), 'user certs copied');
  assert(!complexRoot.ovpnserver, 'OpenVPN wizard state must not be copied');
  assert(!complexRoot.dyndnses, 'legacy dyndnses must not be copied');
  assert(complexRoot.OPNsense.DynDNS.accounts.account.length >= 1, 'DynDNS MVC accounts');
  assert(complexRoot.OPNsense.DynDNS.accounts.account[0].service === 'no-ip', 'noip mapped to no-ip');
  assert(asArraySafe(complexRoot.ca).length >= 1, 'CAs copied');
  assert(complexRoot.syslog?.nentries === '1000' || complexRoot.syslog?.nentries === 1000, 'syslog copied');
  assert(asArraySafe(complexRoot.cron?.item).length >= 1, 'cron copied');

  for (const sample of ['sample-files/pfsense-3.xml', 'sample-files/pfsense.xml']) {
    const result = mapPFtoOPN(parse(readFileSync(sample, 'utf8')));
    assert(!(result instanceof Error), `${sample} should convert`);
    const converted = (result as Exclude<typeof result, Error>).root.opnsense as any;
    assert(converted.OPNsense.Firewall, `${sample} has MVC firewall`);
  }

  const converter = new ConverterService();
  const good = await converter.convertFile(new File([xml], 'pfsense-2.7.0.xml', { type: 'text/xml' }));
  assert(good.validation.canDownload, failSummary('pfSense 2.7.0', good.validation.checks));
  assert(good.validation.errors === 0, '2.7.0 should have no failing checks');
  assert(!!good.xml && good.xml.includes('<opnsense>'), 'downloadable XML is produced after validators pass');
  assert(!good.xml.includes('<pfsense>'), 'downloadable XML is OPNsense, not pfSense');

  const complexOut = await converter.convertFile(
    new File([readFileSync('sample-files/complex-pfsense.xml')], 'complex-pfsense.xml', { type: 'text/xml' })
  );
  assert(complexOut.validation.canDownload, failSummary('complex pfSense', complexOut.validation.checks));
  assert(complexOut.validation.checks.some((check) => check.id === 'input-revision' && check.status === 'warn'), 'old revision warns');
  assert(complexOut.validation.checks.some((check) => check.id === 'output-openvpn' && check.status === 'pass'), 'OpenVPN Instances check');
  assert(complexOut.validation.checks.some((check) => check.id === 'output-trust' && (check.status === 'pass' || check.status === 'warn')), 'certificates verified');
  assert(complexOut.validation.checks.some((check) => check.id === 'output-dyndns' && check.status === 'pass'), 'DynDNS MVC check');
  assert(complexOut.validation.checks.some((check) => check.id === 'output-ovpnwizard' && check.status === 'pass'), 'OpenVPN wizard omitted');
  assert(complexOut.validation.checks.some((check) => check.id === 'output-cron' && (check.status === 'pass' || check.status === 'warn')), 'cron verified');
  assert(complexOut.validation.checks.some((check) => check.id === 'output-syslog' && check.status === 'pass'), 'syslog verified');
  assert(!complexOut.xml.includes('<ovpnserver>'), 'wizard XML omitted');
  assert(!complexOut.xml.includes('<dyndnses>'), 'legacy dyndnses omitted');
  assert(complexOut.xml.includes('<DynDNS>'), 'DynDNS MVC XML present');
  assert(!!complexOut.xml, 'warnings still allow downloadable XML');

  const opnsenseIn = await converter.convertFile(
    new File([readFileSync('sample-files/opnsense.xml')], 'opnsense.xml', { type: 'text/xml' })
  );
  assert(!opnsenseIn.validation.canDownload, 'OPNsense-as-input must not be downloadable');
  assert(!opnsenseIn.xml, 'no XML is returned when validators fail');
  assert(opnsenseIn.validation.checks.some((check) => check.id === 'input-root' && check.status === 'fail'), 'rejects OPNsense root');
  assert(opnsenseIn.validation.checks.filter((check) => check.group === 'output').every((check) => check.status === 'skip'), 'output checks skipped after input fail');

  const garbage = await converter.convertFile(new File(['this is not xml'], 'broken.xml', { type: 'text/xml' }));
  assert(!garbage.validation.canDownload, 'invalid XML is blocked');
  assert(!garbage.xml, 'invalid XML produces no download');
  assert(garbage.validation.checks.some((check) => check.id === 'input-xml' && check.status === 'fail'), 'well-formed XML check fails');
  assert(garbage.validation.checks.filter((check) => check.id !== 'input-xml').every((check) => check.status === 'skip'), 'later checks skipped after XML fail');

  console.log('mapper checks passed');
  console.log(JSON.stringify(mapped.report.stats, null, 2));
  console.log(mapped.report.notes.join('\n'));
  console.log(mapped.report.skipped.join('\n'));
  console.log('validators', {
    pfsense270: { passed: good.validation.passed, warnings: good.validation.warnings, errors: good.validation.errors },
    complex: { passed: complexOut.validation.passed, warnings: complexOut.validation.warnings, errors: complexOut.validation.errors },
  });
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
