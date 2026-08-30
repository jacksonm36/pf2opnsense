import { TestBed } from '@angular/core/testing';

import { ConverterService } from './converter.service';
import { mapPFtoOPN } from '../mappings/pfsense-to-opnsense';

describe('ConverterService', () => {
  let service: ConverterService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(ConverterService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('serializes MVC aliases and filter rules as OPNsense 26.7 XML', () => {
    const mapped = mapPFtoOPN({
      pfsense: {
        version: '22.9',
        system: { hostname: 'fw', domain: 'lab', user: { name: 'root', uid: '0', 'bcrypt-hash': 'x' } },
        interfaces: { lan: { enable: '', if: 'em1', ipaddr: '10.0.0.1', subnet: '24' } },
        aliases: { alias: { name: 'Hosts', type: 'host', address: '10.0.0.2 10.0.0.3' } },
        filter: {
          rule: {
            type: 'pass',
            interface: 'lan',
            protocol: 'tcp',
            source: { any: '' },
            destination: { address: '10.0.0.2', port: '80' },
            descr: 'web',
          },
        },
      },
    });
    expect(mapped instanceof Error).toBeFalse();
    const xml = service.jsonToXML((mapped as Exclude<typeof mapped, Error>).root, true, (mapped as Exclude<typeof mapped, Error>).report);
    expect(xml).toContain('<opnsense>');
    expect(xml).toContain('<OPNsense>');
    expect(xml).toContain('<Filter>');
    expect(xml).toContain('<Alias>');
    expect(xml).toContain('10.0.0.2');
    expect(xml).toContain('<ipaddr>10.0.0.1</ipaddr>');
    expect(xml).not.toContain('<installedpackages>');
  });
});
