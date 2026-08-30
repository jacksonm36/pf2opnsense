import { mapPFtoOPN, TARGET } from './pfsense-to-opnsense';
import { XMLParser } from 'fast-xml-parser';
import { ARRAY_TAG_NAMES } from './xml-utils';

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

function sequentialUuid() {
  let n = 0;
  return () => {
    n += 1;
    return `00000000-0000-4000-8000-${n.toString().padStart(12, '0')}`;
  };
}

describe('mapPFtoOPN pfSense 2.7.0 → OPNsense 26.7', () => {
  const pfsense27 = `<?xml version="1.0"?>
<pfsense>
  <version>22.9</version>
  <system>
    <hostname>edge</hostname>
    <domain>lab.local</domain>
    <timezone>Etc/UTC</timezone>
    <language>en_US</language>
    <user>
      <name>admin</name>
      <descr>System Administrator</descr>
      <scope>system</scope>
      <groupname>admins</groupname>
      <bcrypt-hash>$2y$10$examplehash</bcrypt-hash>
      <uid>0</uid>
    </user>
    <group>
      <name>admins</name>
      <description>System Administrators</description>
      <scope>system</scope>
      <gid>1999</gid>
      <member>0</member>
      <priv>page-all</priv>
    </group>
    <dnsserver>1.1.1.1</dnsserver>
    <dnsserver>8.8.8.8</dnsserver>
  </system>
  <interfaces>
    <wan>
      <enable></enable>
      <if>em0</if>
      <ipaddr>dhcp</ipaddr>
      <subnet></subnet>
      <blockpriv>1</blockpriv>
    </wan>
    <lan>
      <enable></enable>
      <if>em1</if>
      <descr>LAN</descr>
      <ipaddr>192.168.1.1</ipaddr>
      <subnet>24</subnet>
    </lan>
  </interfaces>
  <vlans>
    <vlan>
      <if>em1</if>
      <tag>10</tag>
      <vlanif>em1.10</vlanif>
      <descr>VOICE</descr>
    </vlan>
  </vlans>
  <nat>
    <outbound>
      <mode>automatic</mode>
    </outbound>
    <rule>
      <protocol>tcp</protocol>
      <interface>wan</interface>
      <source>
        <any></any>
      </source>
      <destination>
        <any></any>
      </destination>
      <target>192.168.1.10</target>
      <local-port>443</local-port>
      <descr>HTTPS server</descr>
    </rule>
  </nat>
  <filter>
    <rule>
      <type>pass</type>
      <interface>lan</interface>
      <ipprotocol>inet</ipprotocol>
      <protocol>any</protocol>
      <source>
        <network>lan</network>
      </source>
      <destination>
        <any></any>
      </destination>
      <descr>Allow LAN</descr>
    </rule>
    <rule>
      <type>pass</type>
      <interface>wan</interface>
      <protocol>icmp</protocol>
      <icmptype>echoreq</icmptype>
      <source>
        <any></any>
      </source>
      <destination>
        <any></any>
      </destination>
      <descr>WAN ping</descr>
    </rule>
    <rule>
      <type>match</type>
      <interface>lan</interface>
      <protocol>tcp</protocol>
      <source>
        <any></any>
      </source>
      <destination>
        <any></any>
      </destination>
      <descr>shaper match</descr>
    </rule>
    <rule>
      <type>pass</type>
      <interface>wan</interface>
      <protocol>tcp</protocol>
      <source>
        <any></any>
      </source>
      <destination>
        <address>203.0.113.10</address>
        <port>22</port>
      </destination>
      <descr>Allow SSH</descr>
    </rule>
  </filter>
  <aliases>
    <alias>
      <name>Servers</name>
      <type>host</type>
      <address>192.168.1.10 192.168.1.11</address>
      <descr>LAN servers</descr>
    </alias>
  </aliases>
  <dhcpd>
    <lan>
      <enable></enable>
      <range>
        <from>192.168.1.100</from>
        <to>192.168.1.199</to>
      </range>
      <staticmap>
        <mac>aa:bb:cc:dd:ee:ff</mac>
        <ipaddr>192.168.1.20</ipaddr>
        <hostname>printer</hostname>
      </staticmap>
    </lan>
  </dhcpd>
  <gateways>
    <gateway_item>
      <interface>wan</interface>
      <gateway>dynamic</gateway>
      <name>WAN_DHCP</name>
      <weight>20</weight>
      <ipprotocol>inet</ipprotocol>
      <descr>Interface WAN_DHCP Gateway</descr>
      <defaultgw></defaultgw>
    </gateway_item>
  </gateways>
  <installedpackages>
    <pfblockerng></pfblockerng>
  </installedpackages>
</pfsense>`;

  it('emits OPNsense 26.7 MVC filter rules, aliases, gateways, and dnsmasq DHCP', () => {
    const mapped = mapPFtoOPN(parse(pfsense27), { uuid: sequentialUuid() });
    expect(mapped instanceof Error).toBeFalse();
    const root = (mapped as Exclude<typeof mapped, Error>).root.opnsense as any;
    const report = (mapped as Exclude<typeof mapped, Error>).report;

    expect(root.system.hostname).toBe('edge');
    expect(root.system.user[0].name).toBe('root');
    expect(root.system.user[0].password).toBe('$2y$10$examplehash');
    expect(root.interfaces.lan.ipaddr).toBe('192.168.1.1');
    expect(root.interfaces.lan.subnet).toBe('24');
    expect(root.interfaces.wan.if).toBe('em0');
    expect(root.vlans.vlan[0].tag).toBe('10');

    const rules = root.OPNsense.Firewall.Filter.rules.rule;
    expect(rules.length).toBe(3);
    expect(rules[0].action).toBe('pass');
    expect(rules[0].interface).toBe('lan');
    expect(rules[0].source_net).toBe('lan');
    expect(rules[0].destination_net).toBe('any');
    expect(rules[1].icmptype).toBe('echoreq');
    expect(rules[2].destination_net).toBe('203.0.113.10');
    expect(rules[2].destination_port).toBe('22');
    expect(report.stats.skippedMatchRules).toBe(1);

    const alias = root.OPNsense.Firewall.Alias.aliases.alias[0];
    expect(alias.name).toBe('Servers');
    expect(alias.content).toBe('192.168.1.10\n192.168.1.11');

    expect(root.OPNsense.Gateways.gateway_item[0].weight).toBe('10');
    expect(root.OPNsense.Gateways.gateway_item[0].interface).toBe('wan');

    expect(root.dnsmasq.dhcp_ranges[0].start_addr).toBe('192.168.1.100');
    expect(root.dnsmasq.hosts[0].hwaddr).toBe('aa:bb:cc:dd:ee:ff');
    expect(root.nat.rule[0].target).toBe('192.168.1.10');
    expect(root.filter).toEqual({});
    expect(root.installedpackages).toBeUndefined();
    expect(report.notes.join(' ')).toContain(TARGET.opnsenseRelease);
  });

  it('still maps the legacy toy firewall.rule sample', () => {
    const xml = `<?xml version="1.0"?>
<pfsense>
  <version>2.5.1</version>
  <system>
    <hostname>my-pfsense-firewall</hostname>
    <domain>localdomain</domain>
    <timezone>UTC</timezone>
  </system>
  <interfaces>
    <lan>
      <if>em0</if>
      <ipaddr>192.168.1.1</ipaddr>
      <subnet>24</subnet>
    </lan>
  </interfaces>
  <firewall>
    <rule>
      <if>WAN</if>
      <descr>Allow SSH Inbound</descr>
      <proto>tcp</proto>
      <src>any</src>
      <dst>203.0.113.1</dst>
      <dstport>22</dstport>
    </rule>
  </firewall>
</pfsense>`;
    const mapped = mapPFtoOPN(parse(xml), { uuid: sequentialUuid() });
    expect(mapped instanceof Error).toBeFalse();
    const root = (mapped as Exclude<typeof mapped, Error>).root.opnsense as any;
    const rule = root.OPNsense.Firewall.Filter.rules.rule[0];
    expect(rule.interface).toBe('wan');
    expect(rule.protocol).toBe('tcp');
    expect(rule.destination_net).toBe('203.0.113.1');
    expect(rule.destination_port).toBe('22');
    expect(root.interfaces.lan.ipaddr).toBe('192.168.1.1');
  });

  it('rejects files that are not pfsense configs', () => {
    const mapped = mapPFtoOPN({ opnsense: {} });
    expect(mapped instanceof Error).toBeTrue();
  });
});
