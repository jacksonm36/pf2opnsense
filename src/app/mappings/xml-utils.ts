/** Tags that must always deserialize as arrays (single or repeating). */
export const ARRAY_TAG_NAMES = new Set([
  'alias',
  'rule',
  'user',
  'group',
  'dnsserver',
  'winsserver',
  'radnsserver',
  'ntpserver',
  'gateway_item',
  'gateway_group',
  'staticmap',
  'vlan',
  'lagg',
  'bridged',
  'cert',
  'ca',
  'crl',
  'priv',
  'member',
  'item',
  'hosts',
  'dhcp_ranges',
  'openvpn-server',
  'openvpn-client',
  'openvpn-csc',
  'onetoone',
  'vip',
  'phase1',
  'phase2',
  'route',
  'package',
  'account',
  'dyndns',
  'ppp',
  'mobilekey',
]);

export function asArray<T>(value: T | T[] | undefined | null): T[] {
  if (value === undefined || value === null || value === ('' as unknown as T)) {
    return [];
  }
  return Array.isArray(value) ? value : [value];
}

export function asString(value: unknown): string {
  if (value === undefined || value === null) {
    return '';
  }
  if (typeof value === 'object') {
    const record = value as Record<string, unknown>;
    if (record['#text'] != null) {
      return String(record['#text']);
    }
    if (record['CDATA'] != null) {
      return String(record['CDATA']);
    }
    if (Object.keys(record).length === 0) {
      return '';
    }
  }
  return String(value);
}

/** pfSense empty tags (`<disabled/>`, `<enable></enable>`) mean the flag is set. */
export function flagSet(value: unknown): boolean {
  if (value === undefined || value === null || value === false) {
    return false;
  }
  if (value === 0 || value === '0') {
    return false;
  }
  return true;
}

export function bool01(value: boolean | unknown): '0' | '1' {
  return flagSet(value) ? '1' : '0';
}

export function present01(value: unknown): '0' | '1' {
  return flagSet(value) ? '1' : '0';
}

/** pfSense yes/on flags (empty means off, unlike enable/disabled tags). */
export function yesFlag(value: unknown): boolean {
  const raw = asString(value).trim().toLowerCase();
  return raw === 'yes' || raw === 'on' || raw === '1' || raw === 'true';
}

export function clampInt(value: unknown, min: number, max: number, fallback: number): number {
  const parsed = parseInt(asString(value), 10);
  if (Number.isNaN(parsed)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, parsed));
}

export function lowercaseIdent(value: unknown): string {
  return asString(value).trim().toLowerCase();
}

export function splitList(value: unknown): string[] {
  const raw = asString(value).trim();
  if (!raw) {
    return [];
  }
  return raw
    .split(/[\s,]+/)
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
}
