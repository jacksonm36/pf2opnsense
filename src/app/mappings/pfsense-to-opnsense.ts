import { v4 as uuidv4 } from 'uuid';
import {
  asArray,
  asString,
  bool01,
  clampInt,
  flagSet,
  lowercaseIdent,
  present01,
  splitList,
  yesFlag,
} from './xml-utils';

/** OPNsense 26.7 series (including 26.7.3) and pfSense 2.7.0 (config rev 22.9). */
export const TARGET = {
  opnsenseSeries: '26.7',
  opnsenseRelease: '26.7.3',
  pfsenseRelease: '2.7.0',
  pfsenseConfigRevision: '22.9',
};

export interface ConversionStats {
  filterRules: number;
  skippedMatchRules: number;
  skippedSeparators: number;
  aliases: number;
  gateways: number;
  dhcpRanges: number;
  dhcpHosts: number;
  natPortForwards: number;
  users: number;
  openvpnServers: number;
  openvpnClients: number;
  openvpnUsers: number;
  userCerts: number;
  packages: number;
}

export interface ConversionNotes {
  notes: string[];
  skipped: string[];
  stats: ConversionStats;
}

export interface MapOptions {
  uuid?: () => string;
}

export interface MappedConfig {
  root: { opnsense: Record<string, unknown> };
  report: ConversionNotes;
}

const ALIAS_TYPES = new Set([
  'host',
  'network',
  'port',
  'url',
  'urltable',
  'urljson',
  'geoip',
  'networkgroup',
  'mac',
  'asn',
  'dynipv6host',
  'authgroup',
  'external',
]);

const FILTER_ACTIONS = new Set(['pass', 'block', 'reject']);

const STATE_TYPES: Record<string, string> = {
  keep: 'keep',
  'keep state': 'keep',
  sloppy: 'sloppy',
  'sloppy state': 'sloppy',
  modulate: 'modulate',
  'modulate state': 'modulate',
  synproxy: 'synproxy',
  'synproxy state': 'synproxy',
  none: 'none',
  'no state': 'none',
};

const ICMP_TYPES = new Set([
  'echoreq',
  'echorep',
  'unreach',
  'redir',
  'routeradv',
  'routersol',
  'timex',
  'paramprob',
  'timereq',
  'timerep',
  'photuris',
]);

const INTERFACE_KEEP = new Set([
  'enable',
  'if',
  'descr',
  'ipaddr',
  'subnet',
  'gateway',
  'ipaddrv6',
  'subnetv6',
  'gatewayv6',
  'blockpriv',
  'blockbogons',
  'spoofmac',
  'dhcphostname',
  'dhcprejectfrom',
  'media',
  'mediaopt',
  'mtu',
  'mss',
  'track6-interface',
  'track6-prefix-id',
  'dhcp6-ia-pd-len',
  'dhcp6-ia-pd-enable',
  'prefix-6rd',
  'gateway-6rd',
  'alias-address',
  'alias-subnet',
]);

function nextUuid(options?: MapOptions): string {
  return options?.uuid ? options.uuid() : uuidv4();
}

function endpointNet(endpoint: any): { net: string; not: '0' | '1'; port: string } {
  if (!endpoint || typeof endpoint !== 'object') {
    return { net: 'any', not: '0', port: '' };
  }
  const not = present01(endpoint.not);
  const port = asString(endpoint.port);
  if (flagSet(endpoint.any) || asString(endpoint.any) === '') {
    if (endpoint.any !== undefined) {
      return { net: 'any', not, port };
    }
  }
  if (endpoint.network != null && asString(endpoint.network) !== '') {
    return { net: asString(endpoint.network), not, port };
  }
  if (endpoint.address != null && asString(endpoint.address) !== '') {
    return { net: asString(endpoint.address), not, port };
  }
  return { net: 'any', not, port };
}

function mapProtocol(value: unknown): string {
  const proto = asString(value).trim();
  if (!proto) {
    return 'any';
  }
  if (proto === 'tcp/udp' || proto === 'TCP/UDP') {
    return 'TCP/UDP';
  }
  return proto.toLowerCase() === 'tcp/udp' ? 'TCP/UDP' : proto;
}

function mapStateType(value: unknown): string {
  const raw = asString(value).trim().toLowerCase();
  return STATE_TYPES[raw] || 'keep';
}

function mapIcmpType(rule: any): string | undefined {
  const raw = asString(rule?.icmptype).trim();
  if (!raw || raw === 'any') {
    return undefined;
  }
  const types = raw
    .split(',')
    .map((part) => part.trim())
    .filter((part) => ICMP_TYPES.has(part));
  return types.length ? types.join(',') : undefined;
}

function collectFilterRules(pfsense: any): any[] {
  const fromFilter = asArray(pfsense?.filter?.rule);
  const fromFirewall = asArray(pfsense?.firewall?.rule);
  return [...fromFilter, ...fromFirewall];
}

function mapFilterRule(rule: any, sequence: number, options?: MapOptions): Record<string, unknown> | null {
  if (!rule || typeof rule !== 'object') {
    return null;
  }

  const action = asString(rule.type || rule.action || 'pass').toLowerCase();
  if (action === 'match') {
    return null;
  }
  if (action && !FILTER_ACTIONS.has(action)) {
    return null;
  }

  const iface = lowercaseIdent(rule.interface || rule.if);
  const src = rule.source ? endpointNet(rule.source) : {
    net: asString(rule.src) || 'any',
    not: '0' as const,
    port: asString(rule.srcport),
  };
  const dst = rule.destination ? endpointNet(rule.destination) : {
    net: asString(rule.dst) || 'any',
    not: '0' as const,
    port: asString(rule.dstport),
  };

  const mapped: Record<string, unknown> = {
    '@_uuid': nextUuid(options),
    enabled: flagSet(rule.disabled) ? '0' : '1',
    statetype: mapStateType(rule.statetype),
    sequence: String(sequence),
    action: FILTER_ACTIONS.has(action) ? action : 'pass',
    quick: flagSet(rule.floating) ? present01(rule.quick === undefined ? true : rule.quick) : '1',
    interfacenot: '0',
    interface: iface,
    direction: asString(rule.direction) || (flagSet(rule.floating) ? 'in' : 'in'),
    ipprotocol: asString(rule.ipprotocol) || 'inet',
    protocol: mapProtocol(rule.protocol || rule.proto),
    source_net: src.net || 'any',
    source_not: src.not,
    source_port: src.port,
    destination_net: dst.net || 'any',
    destination_not: dst.not,
    destination_port: dst.port,
    disablereplyto: present01(rule.disablereplyto),
    log: present01(rule.log),
    allowopts: present01(rule.allowopts),
    nosync: present01(rule.nosync),
    nopfsync: present01(rule.nopfsync),
    tcpflags_any: present01(rule.tcpflags_any),
    description: asString(rule.descr || rule.description),
  };

  const icmp = mapIcmpType(rule);
  if (icmp) {
    mapped['icmptype'] = icmp;
  }
  const gateway = asString(rule.gateway);
  if (gateway) {
    mapped['gateway'] = gateway;
  }
  if (flagSet(rule.floating)) {
    mapped['interface'] = iface;
  }

  return mapped;
}

function mapAlias(alias: any, options?: MapOptions): Record<string, unknown> | null {
  if (!alias || typeof alias !== 'object') {
    return null;
  }
  const name = asString(alias.name);
  if (!name) {
    return null;
  }
  let type = asString(alias.type) || 'host';
  if (type === 'urltable_ports') {
    type = 'urltable';
  }
  if (!ALIAS_TYPES.has(type)) {
    type = type.includes('port') ? 'port' : 'host';
  }

  const contentParts = [
    ...splitList(alias.address),
    ...splitList(alias.content),
    ...splitList(alias.url),
  ];
  const uniqueContent = Array.from(new Set(contentParts));

  const mapped: Record<string, unknown> = {
    '@_uuid': asString(alias['@_uuid']) || nextUuid(options),
    enabled: alias.enabled === undefined ? '1' : present01(alias.enabled),
    name,
    type,
    content: uniqueContent.join('\n'),
    description: asString(alias.descr || alias.description),
  };
  if (asString(alias.proto)) {
    mapped['proto'] = asString(alias.proto);
  }
  if (asString(alias.interface)) {
    mapped['interface'] = asString(alias.interface);
  }
  if (flagSet(alias.counters)) {
    mapped['counters'] = '1';
  }
  if (asString(alias.updatefreq)) {
    mapped['updatefreq'] = asString(alias.updatefreq);
  }
  if (asString(alias.categories)) {
    mapped['categories'] = asString(alias.categories);
  }
  return mapped;
}

function mapUser(user: any): Record<string, unknown> | null {
  if (!user || typeof user !== 'object') {
    return null;
  }
  const mapped: Record<string, unknown> = {
    name: asString(user.name),
    descr: asString(user.descr),
    scope: asString(user.scope) || 'system',
    groupname: asString(user.groupname),
    uid: asString(user.uid),
  };
  const password =
    asString(user.password) ||
    asString(user['bcrypt-hash']) ||
    asString(user['sha512-hash']) ||
    asString(user['md5-hash']);
  mapped['password'] = password;
  const priv = asArray(user.priv).map(asString).filter(Boolean);
  if (priv.length === 1) {
    mapped['priv'] = priv[0];
  } else if (priv.length > 1) {
    mapped['priv'] = priv;
  }
  if (asString(user.expires)) {
    mapped['expires'] = asString(user.expires);
  }
  if (asString(user.authorizedkeys)) {
    mapped['authorizedkeys'] = asString(user.authorizedkeys);
  }
  return mapped['name'] ? mapped : null;
}

function mapSystem(pfsense: any, report: ConversionNotes): Record<string, unknown> {
  const src = pfsense?.system || {};
  const users = asArray(src.user)
    .map(mapUser)
    .filter((user): user is Record<string, unknown> => !!user);

  for (const user of users) {
    if (asString(user['uid']) === '0' && asString(user['name']) !== 'root') {
      report.notes.push(
        `Renamed uid 0 user "${asString(user['name'])}" to "root" (OPNsense requires the root account).`
      );
      user['name'] = 'root';
    }
  }

  const groups = asArray(src.group).map((group: any) => ({
    name: asString(group.name),
    description: asString(group.description),
    scope: asString(group.scope) || 'system',
    gid: asString(group.gid),
    member: asArray(group.member).map(asString),
    priv: asArray(group.priv).map(asString),
  }));

  const webguiSrc = src.webgui || {};
  const system: Record<string, unknown> = {
    optimization: asString(src.optimization) || 'normal',
    hostname: asString(src.hostname) || 'OPNsense',
    domain: asString(src.domain) || 'internal',
    timezone: asString(src.timezone) || 'Etc/UTC',
    language: asString(src.language) || 'en_US',
    timeservers: asString(src.timeservers) || '0.opnsense.pool.ntp.org 1.opnsense.pool.ntp.org 2.opnsense.pool.ntp.org 3.opnsense.pool.ntp.org',
    dnsallowoverride: present01(src.dnsallowoverride),
    group: groups.length ? groups : undefined,
    user: users,
    webgui: {
      protocol: asString(webguiSrc.protocol) || 'https',
    },
    disablenatreflection: asString(src.disablenatreflection) || 'yes',
    ipv6allow: flagSet(src.ipv6allow) ? '1' : undefined,
    bogons: src.bogons || { interval: 'monthly' },
    ssh: flagSet(src.enablesshd) || src.ssh ? { group: 'admins' } : undefined,
  };

  const dns = asArray(src.dnsserver).map(asString).filter(Boolean);
  if (dns.length) {
    system['dnsserver'] = dns;
  }

  report.stats.users = users.length;
  return system;
}

function mapInterfaces(pfsense: any, report: ConversionNotes): Record<string, unknown> {
  const src = pfsense?.interfaces || {};
  const mapped: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(src)) {
    const iface = Array.isArray(value) ? value[0] : value;
    if (!iface || typeof iface !== 'object') {
      continue;
    }
    if (Array.isArray(value) && value.length > 1) {
      report.notes.push(
        `Interface "${name}" had multiple blocks; kept the first. Check assignments on OPNsense.`
      );
    }
    const clean: Record<string, unknown> = {};
    for (const [key, field] of Object.entries(iface as Record<string, unknown>)) {
      if (!INTERFACE_KEEP.has(key)) {
        continue;
      }
      if (key === 'enable') {
        clean['enable'] = flagSet(field) || field === '' ? '1' : present01(field);
        continue;
      }
      clean[key] = asString(field);
    }
    if (clean['enable'] === undefined && (clean['if'] || clean['ipaddr'])) {
      clean['enable'] = '1';
    }
    mapped[name] = clean;
  }
  if (!Object.keys(mapped).length) {
    report.skipped.push('No interface assignments found in the pfSense config.');
  }
  return mapped;
}

function mapVlans(pfsense: any): Record<string, unknown> | undefined {
  const vlans = asArray(pfsense?.vlans?.vlan);
  if (!vlans.length) {
    return undefined;
  }
  return {
    vlan: vlans.map((vlan: any) => ({
      if: asString(vlan.if),
      tag: asString(vlan.tag),
      pcp: asString(vlan.pcp) || '0',
      proto: asString(vlan.proto),
      descr: asString(vlan.descr),
      vlanif: asString(vlan.vlanif),
    })),
  };
}

function mapGateways(pfsense: any, options: MapOptions | undefined, report: ConversionNotes): Record<string, unknown> | undefined {
  const items = asArray(pfsense?.gateways?.gateway_item);
  if (!items.length) {
    return undefined;
  }
  const mapped = items.map((item: any) => {
    const weight = clampInt(item.weight, 1, 10, 1);
    if (clampInt(item.weight, 1, 30, 1) > 10) {
      report.notes.push(
        `Clamped gateway "${asString(item.name)}" weight from ${asString(item.weight)} to 10 (OPNsense max).`
      );
    }
    return {
      '@_uuid': nextUuid(options),
      disabled: present01(item.disabled),
      name: asString(item.name),
      descr: asString(item.descr),
      interface: lowercaseIdent(item.interface) || 'wan',
      ipprotocol: asString(item.ipprotocol) || 'inet',
      gateway: asString(item.gateway),
      defaultgw: present01(item.defaultgw),
      monitor_disable: item.monitor_disable === undefined ? '1' : present01(item.monitor_disable),
      priority: String(clampInt(item.priority, 0, 255, 255)),
      weight: String(weight),
    };
  });
  report.stats.gateways = mapped.length;
  return { gateway_item: mapped };
}

function mapDhcpToDnsmasq(pfsense: any, report: ConversionNotes): Record<string, unknown> | undefined {
  const dhcpd = pfsense?.dhcpd;
  const existing = pfsense?.dnsmasq || {};
  const ranges: Record<string, unknown>[] = [];
  const hosts: Record<string, unknown>[] = [];
  const interfaces = new Set<string>();

  if (dhcpd && typeof dhcpd === 'object') {
    for (const [iface, cfg] of Object.entries(dhcpd as Record<string, any>)) {
      if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg)) {
        continue;
      }
      interfaces.add(iface);
      const range = cfg.range || {};
      const from = asString(range.from);
      const to = asString(range.to);
      if (from && to) {
        ranges.push({
          interface: iface,
          start_addr: from,
          end_addr: to,
        });
      }
      for (const staticMap of asArray(cfg.staticmap)) {
        const ip = asString(staticMap.ipaddr);
        const mac = asString(staticMap.mac);
        if (!ip && !mac) {
          continue;
        }
        hosts.push({
          host: asString(staticMap.hostname),
          ip,
          hwaddr: mac,
          descr: asString(staticMap.descr),
        });
      }
    }
  }

  for (const host of asArray(existing.hosts)) {
    hosts.push({
      host: asString(host.host),
      domain: asString(host.domain),
      ip: asString(host.ip),
      descr: asString(host.descr),
    });
  }

  if (!ranges.length && !hosts.length && !flagSet(existing.enable)) {
    return undefined;
  }

  report.stats.dhcpRanges = ranges.length;
  report.stats.dhcpHosts = hosts.length;
  if (ranges.length) {
    report.notes.push(
      `Mapped ISC dhcpd pools to dnsmasq DHCP (${TARGET.opnsenseSeries} default). Review KEA if you prefer that backend.`
    );
  }

  const mapped: Record<string, unknown> = {
    enable: '1',
    port: asString(existing.port) || '53053',
    interface: Array.from(interfaces).join(',') || asString(existing.interface),
    dhcp: {
      enable_ra: '1',
    },
  };
  if (ranges.length) {
    mapped['dhcp_ranges'] = ranges;
  }
  if (hosts.length) {
    mapped['hosts'] = hosts;
  }
  return mapped;
}

function mapNat(pfsense: any, report: ConversionNotes): Record<string, unknown> {
  const nat = pfsense?.nat || {};
  const outbound = nat.outbound || {};
  const mode = asString(outbound.mode) || 'automatic';
  const forwards = asArray(nat.rule).map((rule: any) => {
    const destination = rule.destination ? { ...rule.destination } : {};
    if (destination.address != null) {
      destination.address = asString(destination.address).trim();
    }
    return {
      protocol: mapProtocol(rule.protocol),
      interface: lowercaseIdent(rule.interface),
      ipprotocol: asString(rule.ipprotocol) || 'inet',
      source: rule.source || { any: '' },
      destination,
      target: asString(rule.target).trim(),
      'local-port': asString(rule['local-port']),
      descr: asString(rule.descr),
      disabled: flagSet(rule.disabled) ? '1' : undefined,
    };
  });
  report.stats.natPortForwards = forwards.length;
  if (asArray(outbound.rule).length) {
    report.notes.push(
      'Custom outbound NAT rules were kept in legacy format. Use Firewall → NAT → Source NAT migration assistant on OPNsense 26.7 if prompted.'
    );
  }
  const mapped: Record<string, unknown> = {
    outbound: {
      mode,
      rule: asArray(outbound.rule),
    },
  };
  if (forwards.length) {
    mapped['rule'] = forwards;
  }
  return mapped;
}

function copyCompatible(pfsense: any, key: string): unknown {
  return pfsense?.[key];
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

const DYNDNS_SERVICE: Record<string, string> = {
  noip: 'no-ip',
  noipfree: 'no-ip',
  dyndns: 'dyndns',
  dyndns2: 'dyndns',
  namecheap: 'namecheap',
  duckdns: 'duck-dns',
  cloudflare: 'cloudflare',
  godaddy: 'godaddy',
  freedns: 'freedns',
  google: 'google',
  he: 'he-net',
  henet: 'he-net',
  route53: 'route53',
  custom: 'custom',
  customv6: 'custom',
  gandi: 'gandi-net',
  strato: 'strato',
  ovh: 'ovh',
  dnsmadeeasy: 'dnsmadeeasy',
};

function mapDynDnsService(type: string): string {
  const key = type.toLowerCase().replace(/[^a-z0-9]+/g, '');
  return DYNDNS_SERVICE[key] || (type ? type.toLowerCase() : 'custom');
}

function mapDynDns(pfsense: any, options: MapOptions | undefined, report: ConversionNotes): Record<string, unknown> | undefined {
  const rows = asArray(pfsense?.dyndnses?.dyndns).filter((row: any) => {
    return asString(row?.type) || asString(row?.host) || asString(row?.username);
  });
  if (!rows.length) {
    return undefined;
  }

  const accounts = rows.map((row: any) => {
    const service = mapDynDnsService(asString(row.type));
    if (!DYNDNS_SERVICE[asString(row.type).toLowerCase().replace(/[^a-z0-9]+/g, '')]) {
      report.notes.push(
        `DynDNS "${asString(row.host) || asString(row.descr) || service}" uses pfSense type "${asString(row.type)}"; mapped as OPNsense service "${service}". Confirm under Services → Dynamic DNS.`
      );
    }
    return {
      '@_uuid': nextUuid(options),
      enabled: flagSet(row.enable) ? '1' : '0',
      service,
      username: asString(row.username),
      password: asString(row.password),
      hostnames: asString(row.host),
      description: asString(row.descr),
      interface: lowercaseIdent(row.interface || row.requestif) || 'wan',
      checkip: 'if',
      force_ssl: '1',
    };
  });

  report.notes.push(
    `Mapped ${accounts.length} DynDNS account(s) to OPNsense DynDNS (os-ddclient). Install os-ddclient if it is not already present.`
  );

  return {
    general: {
      enabled: '1',
      verbose: '0',
      interval: '300',
      backend: 'opnsense',
    },
    accounts: { account: accounts },
  };
}

const PACKAGE_TO_PLUGIN: Record<string, string> = {
  'openvpn-client-export': 'os-openvpn-client-export',
  'openvpn client export utility': 'os-openvpn-client-export',
  wireguard: 'os-wireguard',
  acme: 'os-acme-client',
  'acme-client': 'os-acme-client',
  nmap: 'os-nmap',
  iperf: 'os-iperf',
  lldpd: 'os-lldpd',
  'mdns-repeater': 'os-mdns-repeater',
  avahi: 'os-mdns-repeater',
  nut: 'os-nut',
  frr: 'os-frr',
  bind: 'os-bind',
  haproxy: 'os-haproxy',
  nginx: 'os-nginx',
  squid: 'os-squid',
  telegraf: 'os-telegraf',
  'zabbix-agent': 'os-zabbix-agent',
  ntopng: 'os-ntopng',
  vnstat: 'os-vnstat',
  nrpe: 'os-nrpe',
  stunnel: 'os-stunnel',
  tinc: 'os-tinc',
  maltrail: 'os-maltrail',
  crowdsec: 'os-crowdsec',
  smartmontools: 'os-smart',
  wol: 'os-wol',
  dyndns: 'os-ddclient',
  rfc2136: 'os-ddclient',
  apcupsd: 'os-apcupsd',
  suricata: 'os-suricata',
  snort: 'os-suricata',
};

function decodeBase64Text(value: string): string | null {
  try {
    const BufferCtor = (globalThis as { Buffer?: { from: (data: string, enc: string) => { toString: (enc: string) => string } } }).Buffer;
    if (BufferCtor) {
      return BufferCtor.from(value, 'base64').toString('utf8');
    }
    if (typeof atob === 'function') {
      return atob(value);
    }
  } catch {
    return null;
  }
  return null;
}

function decodeTlsKey(raw: unknown): string {
  const trimmed = asString(raw).trim();
  if (!trimmed) {
    return '';
  }
  if (/BEGIN OpenVPN Static key/i.test(trimmed)) {
    return trimmed.replace(/\r\n/g, '\n');
  }
  const decoded = decodeBase64Text(trimmed.replace(/\s+/g, ''));
  if (decoded && /BEGIN OpenVPN Static key|OpenVPN static key/i.test(decoded)) {
    return decoded.replace(/\r\n/g, '\n').trim();
  }
  return trimmed;
}

function mapOvpnProto(value: unknown): string {
  const proto = asString(value).toLowerCase().replace(/[^a-z0-9]/g, '');
  if (proto === 'udp4' || proto === 'udpipv4') {
    return 'udp4';
  }
  if (proto === 'udp6' || proto === 'udpipv6') {
    return 'udp6';
  }
  if (proto === 'tcp4' || proto === 'tcpipv4') {
    return 'tcp4';
  }
  if (proto === 'tcp6' || proto === 'tcpipv6') {
    return 'tcp6';
  }
  if (proto.startsWith('tcp')) {
    return 'tcp';
  }
  if (proto.startsWith('udp')) {
    return 'udp';
  }
  return 'udp';
}

function mapOvpnDigest(value: unknown): string {
  const digest = asString(value).trim();
  if (!digest) {
    return '';
  }
  const upper = digest.toUpperCase().replace(/[^A-Z0-9-]/g, '');
  if (upper === 'SHA1' || upper === 'SHA256' || upper === 'SHA512' || upper === 'SHA384' || upper === 'SHA224') {
    return upper;
  }
  return digest;
}

function mapOvpnCiphers(node: any): { ciphers: string; fallback: string } {
  const ncp = asString(node?.['ncp-ciphers'] || node?.ncp_ciphers)
    .split(/[:,\s]+/)
    .map((part) => part.trim())
    .filter(Boolean);
  const crypto = asString(node?.crypto || node?.data_ciphers).trim();
  const unique = Array.from(new Set([...ncp, crypto].filter(Boolean)));
  return {
    ciphers: unique.join(','),
    fallback: crypto,
  };
}

function mapOvpnDevType(value: unknown): string {
  const dev = asString(value).toLowerCase();
  if (dev === 'tap') {
    return 'tap';
  }
  return 'tun';
}

function mapOpenVpn(
  pfsense: any,
  options: MapOptions | undefined,
  report: ConversionNotes
): Record<string, unknown> | undefined {
  const ovpn = pfsense?.openvpn || {};
  const servers = asArray(ovpn['openvpn-server']);
  const clients = asArray(ovpn['openvpn-client']);
  const cscs = asArray(ovpn['openvpn-csc']).filter(
    (csc: any) => asString(csc?.common_name)
  );

  report.stats.openvpnServers = servers.length;
  report.stats.openvpnClients = clients.length;
  report.stats.openvpnUsers = cscs.length;

  const userCerts = asArray(pfsense?.cert).filter(
    (cert: any) => asString(cert?.type).toLowerCase() === 'user'
  );
  report.stats.userCerts = userCerts.length;

  if (!servers.length && !clients.length && !cscs.length) {
    return undefined;
  }

  const staticKeys: Record<string, unknown>[] = [];
  const tlsKeyByMaterial = new Map<string, string>();

  const ensureStaticKey = (node: any, label: string): string => {
    const material = decodeTlsKey(node?.tls);
    if (!material) {
      return '';
    }
    const existing = tlsKeyByMaterial.get(material);
    if (existing) {
      return existing;
    }
    const uuid = nextUuid(options);
    const tlsType = asString(node?.tls_type).toLowerCase();
    const mode = tlsType === 'auth' ? 'auth' : tlsType.includes('v2') ? 'crypt-v2' : 'crypt';
    staticKeys.push({
      '@_uuid': uuid,
      mode,
      key: material,
      description: `${label} TLS static key`,
    });
    tlsKeyByMaterial.set(material, uuid);
    return uuid;
  };

  const mapInstance = (node: any, role: 'server' | 'client'): Record<string, unknown> => {
    const uuid = nextUuid(options);
    const vpnid = asString(node.vpnid) || String(staticKeys.length + 1);
    const label = asString(node.description || node.descr) || `OpenVPN ${role} ${vpnid}`;
    const ciphers = mapOvpnCiphers(node);
    const flags: string[] = [];
    if (yesFlag(node.client2client)) {
      flags.push('client-to-client');
    }
    if (yesFlag(node.passtos)) {
      flags.push('passtos');
    }
    if (yesFlag(node.duplicate_cn) || yesFlag(node['duplicate-cn'])) {
      flags.push('duplicate-cn');
    }
    if (yesFlag(node.dynamic_ip)) {
      flags.push('float');
    }
    if (yesFlag(node.explicit_exit_notify) || yesFlag(node['explicit-exit-notify'])) {
      flags.push('explicit-exit-notify');
    }

    const instance: Record<string, unknown> = {
      '@_uuid': uuid,
      vpnid,
      enabled: flagSet(node.disable) ? '0' : '1',
      role,
      dev_type: mapOvpnDevType(node.dev_mode),
      verb: asString(node.verbosity_level) || '3',
      proto: mapOvpnProto(node.protocol),
      topology: asString(node.topology) || 'subnet',
      description: label,
      remote_cert_tls: '0',
      verify_client_cert: 'require',
      use_ocsp: '0',
      username_as_common_name: present01(node.username_as_common_name),
      strictusercn: asString(node.strictusercn) || '0',
      provision_exclusive: '0',
      register_dns: present01(node.register_dns),
    };

    const port = asString(node.local_port || node.port);
    if (port) {
      instance['port'] = port;
    }
    if (asString(node.ipaddr)) {
      instance['local'] = asString(node.ipaddr);
    }

    const tunnel = asString(node.tunnel_network);
    const tunnelv6 = asString(node.tunnel_networkv6);
    if (role === 'server' && tunnel) {
      instance['server'] = tunnel;
    }
    if (role === 'server' && tunnelv6) {
      instance['server_ipv6'] = tunnelv6;
    }

    const pushRoute = asString(node.local_network);
    if (pushRoute) {
      instance['push_route'] = pushRoute;
    }
    const remoteNet = asString(node.remote_network);
    if (remoteNet) {
      instance['route'] = remoteNet;
    }

    if (asString(node.certref)) {
      instance['cert'] = asString(node.certref);
    }
    if (asString(node.caref)) {
      instance['ca'] = asString(node.caref);
    }
    if (asString(node.crlref)) {
      instance['crl'] = asString(node.crlref);
    }
    if (asString(node.cert_depth)) {
      instance['cert_depth'] = asString(node.cert_depth);
    }

    const digest = mapOvpnDigest(node.digest);
    if (digest) {
      instance['auth'] = digest;
    }
    if (ciphers.ciphers) {
      instance['data-ciphers'] = ciphers.ciphers;
    }
    if (ciphers.fallback) {
      instance['data-ciphers-fallback'] = ciphers.fallback;
    }

    const tlsUuid = ensureStaticKey(node, label);
    if (tlsUuid) {
      instance['tls_key'] = tlsUuid;
    }

    if (flags.length) {
      instance['various_flags'] = flags.join(',');
    }
    if (yesFlag(node.gwredir)) {
      instance['redirect_gateway'] = 'def1';
    }
    if (asString(node.maxclients)) {
      instance['maxclients'] = asString(node.maxclients);
    }
    if (asString(node.authmode)) {
      instance['authmode'] = asString(node.authmode);
    }

    if (role === 'client') {
      const remoteHost = asString(node.server_addr || node.remote);
      const remotePort = asString(node.server_port || node.port);
      if (remoteHost) {
        instance['remote'] = remotePort ? `${remoteHost} ${remotePort}` : remoteHost;
      }
    }

    if (asString(node.dev_mode).toLowerCase() === 'tap') {
      const start = asString(node.serverbridge_dhcp_start);
      const end = asString(node.serverbridge_dhcp_end);
      if (start && end) {
        instance['bridge_pool'] = `${start} ${end}`;
      }
    }

    if (asString(node.compression) && asString(node.compression) !== 'no') {
      instance['compress_migrate'] = '1';
      report.notes.push(
        `OpenVPN "${label}" used compression (${asString(node.compression)}); OPNsense 26.7 / OpenVPN 2.7 deprecates it. compress_migrate was enabled — test clients.`
      );
    }
    if (asString(node.custom_options)) {
      report.notes.push(
        `OpenVPN "${label}" had custom options that have no Instances field; review VPN → OpenVPN → Instances after import.`
      );
    }

    instance['__uuid'] = uuid;
    instance['__vpnid'] = vpnid;
    return instance;
  };

  const instances = [
    ...servers.map((node: any) => mapInstance(node, 'server')),
    ...clients.map((node: any) => mapInstance(node, 'client')),
  ];
  const serverUuids = instances
    .filter((instance) => instance['role'] === 'server')
    .map((instance) => asString(instance['@_uuid']))
    .join(',');

  const overwrites = cscs.map((csc: any) => {
    const mapped: Record<string, unknown> = {
      '@_uuid': nextUuid(options),
      enabled: '1',
      common_name: asString(csc.common_name),
      block: present01(csc.block),
      push_reset: present01(csc.push_reset),
      description: asString(csc.description || csc.descr),
    };
    if (serverUuids) {
      mapped['servers'] = serverUuids;
    }
    if (asString(csc.tunnel_network)) {
      mapped['tunnel_network'] = asString(csc.tunnel_network);
    }
    if (asString(csc.tunnel_networkv6)) {
      mapped['tunnel_networkv6'] = asString(csc.tunnel_networkv6);
    }
    if (asString(csc.local_network)) {
      mapped['local_networks'] = asString(csc.local_network);
    }
    if (asString(csc.remote_network)) {
      mapped['remote_networks'] = asString(csc.remote_network);
    }
    if (yesFlag(csc.gwredir)) {
      mapped['redirect_gateway'] = 'def1';
    }
    return mapped;
  });

  instances.forEach((instance) => {
    delete instance['__uuid'];
    delete instance['__vpnid'];
  });

  report.notes.push(
    `Mapped OpenVPN to OPNsense Instances (new): ${servers.length} server(s), ${clients.length} client(s), ${cscs.length} user overwrite(s), ${staticKeys.length} TLS static key(s)` +
      (userCerts.length ? `, ${userCerts.length} user certificate(s)` : '') +
      '. Legacy VPN → OpenVPN → Servers is not written.'
  );

  const model: Record<string, unknown> = {};
  if (instances.length) {
    model['Instances'] = { Instance: instances };
  }
  if (overwrites.length) {
    model['Overwrites'] = { Overwrite: overwrites };
  }
  if (staticKeys.length) {
    model['StaticKeys'] = { StaticKey: staticKeys };
  }
  return model;
}

function mapPackages(pfsense: any, report: ConversionNotes): Record<string, unknown> | undefined {
  const installed = pfsense?.installedpackages;
  if (!installed || typeof installed !== 'object') {
    return undefined;
  }

  const packages = asArray((installed as any).package);
  const names = packages
    .map((pkg: any) => asString(pkg.internal_name || pkg.name))
    .filter(Boolean);
  const extraKeys = Object.keys(installed).filter((key) => key !== 'package');
  report.stats.packages = names.length || extraKeys.length;

  const plugins = Array.from(
    new Set(
      names
        .map((name) => PACKAGE_TO_PLUGIN[name.toLowerCase()])
        .filter((plugin): plugin is string => !!plugin)
    )
  );

  if (names.length) {
    report.notes.push(
      `Copied pfSense package records (${names.join(', ')}). These will not run on OPNsense; install matching plugins where they exist` +
        (plugins.length ? `: ${plugins.join(', ')}` : '') +
        '.'
    );
  } else if (extraKeys.length) {
    report.notes.push(
      `Copied pfSense package configuration blocks (${extraKeys.join(', ')}). Review after import; pfSense packages are not OPNsense plugins.`
    );
  }

  return installed as Record<string, unknown>;
}

export function mapPFtoOPN(input: any, options?: MapOptions): MappedConfig | Error {
  const pfsense = input?.pfsense;
  if (pfsense == null) {
    return new Error('Incompatible file type\nMessage:  pfsense object is null');
  }

  const report: ConversionNotes = {
    notes: [
      `Targeting OPNsense ${TARGET.opnsenseRelease} (${TARGET.opnsenseSeries} series) from pfSense ${TARGET.pfsenseRelease} (config revision ${asString(pfsense.version) || TARGET.pfsenseConfigRevision}).`,
    ],
    skipped: [],
    stats: {
      filterRules: 0,
      skippedMatchRules: 0,
      skippedSeparators: 0,
      aliases: 0,
      gateways: 0,
      dhcpRanges: 0,
      dhcpHosts: 0,
      natPortForwards: 0,
      users: 0,
      openvpnServers: 0,
      openvpnClients: 0,
      openvpnUsers: 0,
      userCerts: 0,
      packages: 0,
    },
  };

  const sourceRevision = asString(pfsense.version);
  if (sourceRevision && sourceRevision !== TARGET.pfsenseConfigRevision) {
    report.notes.push(
      `Source config revision is ${sourceRevision}, not ${TARGET.pfsenseConfigRevision} (pfSense ${TARGET.pfsenseRelease}). Mapping still runs; review the result.`
    );
  }

  const rules: Record<string, unknown>[] = [];
  let sequence = 1;
  for (const rule of collectFilterRules(pfsense)) {
    if (rule?.separator != null || (rule && rule.type == null && rule.proto == null && rule.interface == null && rule.if == null && rule.source == null && rule.dst == null)) {
      report.stats.skippedSeparators += 1;
      continue;
    }
    const action = asString(rule?.type || rule?.action).toLowerCase();
    if (action === 'match') {
      report.stats.skippedMatchRules += 1;
      report.skipped.push(`Skipped filter rule "${asString(rule.descr)}" (action=match is not supported on OPNsense).`);
      continue;
    }
    const mapped = mapFilterRule(rule, sequence, options);
    if (mapped) {
      rules.push(mapped);
      sequence += 10;
    }
  }
  report.stats.filterRules = rules.length;

  const aliases = asArray(pfsense?.aliases?.alias)
    .map((alias) => mapAlias(alias, options))
    .filter((alias): alias is Record<string, unknown> => !!alias);
  report.stats.aliases = aliases.length;

  const opnsenseMvc: Record<string, unknown> = {
    Firewall: {
      Alias: {
        aliases: aliases.length ? { alias: aliases } : {},
      },
      Filter: {
        rules: rules.length ? { rule: rules } : {},
        snatrules: {},
        npt: {},
        onetoone: {},
      },
    },
  };

  const gateways = mapGateways(pfsense, options, report);
  if (gateways) {
    opnsenseMvc['Gateways'] = gateways;
  }

  const dnsmasq = mapDhcpToDnsmasq(pfsense, report);
  const vlans = mapVlans(pfsense);
  const openvpn = mapOpenVpn(pfsense, options, report);
  const packages = mapPackages(pfsense, report);
  const dyndns = mapDynDns(pfsense, options, report);

  if (pfsense?.shaper || pfsense?.dnshaper || pfsense?.ezshaper) {
    report.notes.push('Traffic shaping was copied as-is; OPNsense uses a different shaper. Review Firewall → Shaper.');
  }
  if (pfsense?.captiveportal) {
    report.notes.push('Captive portal config was copied; confirm it under Services → Captive Portal after import.');
  }
  if (pfsense?.wireguard || pfsense?.installedpackages?.wireguard) {
    report.notes.push('WireGuard config was copied; install os-wireguard on OPNsense if it is not already present.');
  }

  if (openvpn) {
    opnsenseMvc['OpenVPN'] = openvpn;
  }
  if (dyndns) {
    opnsenseMvc['DynDNS'] = dyndns;
  }

  const opnsense: Record<string, unknown> = {
    theme: 'opnsense',
    system: mapSystem(pfsense, report),
    interfaces: mapInterfaces(pfsense, report),
    nat: mapNat(pfsense, report),
    filter: {},
    unbound: pfsense?.unbound || { enable: '1' },
    rrd: { enable: '' },
    ntpd: {
      prefer: '0.opnsense.pool.ntp.org',
      ispool: '0.opnsense.pool.ntp.org 1.opnsense.pool.ntp.org 2.opnsense.pool.ntp.org 3.opnsense.pool.ntp.org',
    },
    revision: {
      username: 'pf2opn',
      time: String(Date.now() / 1000),
      description: `Converted from pfSense ${TARGET.pfsenseRelease} by pf2opn for OPNsense ${TARGET.opnsenseRelease}`,
    },
    OPNsense: opnsenseMvc,
  };

  if (dnsmasq) {
    opnsense['dnsmasq'] = dnsmasq;
  }
  if (vlans) {
    opnsense['vlans'] = vlans;
  }
  if (packages) {
    opnsense['installedpackages'] = packages;
  }

  const passthrough = [
    'ca',
    'cert',
    'crl',
    'ipsec',
    'staticroutes',
    'virtualip',
    'bridges',
    'laggs',
    'gifs',
    'gres',
    'ppps',
    'wol',
    'syslog',
    'cron',
    'captiveportal',
    'shaper',
    'dnshaper',
    'load_balancer',
    'ifgroups',
    'qinqs',
    'wireless',
    'wireguard',
  ] as const;
  const verifiedPassthrough = new Set(['ca', 'cert', 'crl', 'ipsec', 'ppps', 'syslog', 'cron']);
  for (const key of passthrough) {
    const value = copyCompatible(pfsense, key);
    if (isEmptySection(value)) {
      continue;
    }
    opnsense[key] = value;
    if (!verifiedPassthrough.has(key)) {
      report.notes.push(`Copied ${key} with minimal translation; verify after import.`);
    }
  }

  const groups = asArray(pfsense?.gateways?.gateway_group);
  if (groups.length) {
    opnsense['gateways'] = { gateway_group: groups };
    report.notes.push('Gateway groups were copied in legacy form; confirm them under System → Gateways.');
  }

  return {
    root: { opnsense },
    report,
  };
}

export function buildConversionComment(report: ConversionNotes): string {
  const lines = [
    `Generated by pf2opn for OPNsense ${TARGET.opnsenseRelease}`,
    ...report.notes,
    ...report.skipped,
    `Mapped: ${report.stats.filterRules} filter rules, ${report.stats.aliases} aliases, ${report.stats.gateways} gateways, ${report.stats.dhcpRanges} DHCP ranges, ${report.stats.dhcpHosts} static maps, ${report.stats.natPortForwards} port forwards, ${report.stats.openvpnUsers} OpenVPN users, ${report.stats.packages} packages.`,
  ];
  return lines.join('\n');
}
