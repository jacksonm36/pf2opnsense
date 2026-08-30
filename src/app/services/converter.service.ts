import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable, from } from 'rxjs';
import { XMLBuilder } from 'fast-xml-parser';
import {
  buildConversionComment,
  ConversionNotes,
  mapPFtoOPN,
} from '../mappings/pfsense-to-opnsense';
import { parsePfSenseXml, runValidators, ValidationContext } from './config-checks';
import { ValidationReport } from './validation.types';

export interface ConversionOutput {
  xml: string;
  compactXml: string;
  report: ConversionNotes;
  validation: ValidationReport;
}

@Injectable({
  providedIn: 'root'
})
export class ConverterService {

  displayConversionCard$ = new BehaviorSubject(false);
  conversionAvailable$ = new BehaviorSubject(false);
  conversionReport$ = new BehaviorSubject<ConversionNotes | null>(null);
  validationReport$ = new BehaviorSubject<ValidationReport | null>(null);

  constructor() { }

  cancel() {
    this.displayConversionCard$.next(false);
    this.conversionReport$.next(null);
    this.validationReport$.next(null);
    this.conversionAvailable$.next(false);
  }

  async convert(file: File): Promise<Observable<ConversionOutput>> {
    this.displayConversionCard$.next(true);
    this.conversionAvailable$.next(false);
    this.conversionReport$.next(null);
    this.validationReport$.next(null);

    return from(this.convertFile(file));
  }

  async convertFile(file: File): Promise<ConversionOutput> {
    const text = await file.text();
    const ctx: ValidationContext = {
      fileName: file.name,
      rawText: text,
    };

    const parsed = parsePfSenseXml(text);
    if (!parsed.ok) {
      const validation = runValidators(ctx);
      this.validationReport$.next(validation);
      this.conversionAvailable$.next(false);
      return {
        xml: '',
        compactXml: '',
        report: { notes: [], skipped: [parsed.reason], stats: emptyStats() },
        validation,
      };
    }

    ctx.parsedInput = parsed.parsed;
    if (!parsed.parsed?.pfsense) {
      const validation = runValidators(ctx);
      this.validationReport$.next(validation);
      this.conversionAvailable$.next(false);
      return {
        xml: '',
        compactXml: '',
        report: { notes: [], skipped: ['Not a pfSense configuration backup.'], stats: emptyStats() },
        validation,
      };
    }

    const mapped = mapPFtoOPN(parsed.parsed);
    if (mapped instanceof Error) {
      ctx.convertError = mapped.message;
      const validation = runValidators(ctx);
      this.validationReport$.next(validation);
      this.conversionAvailable$.next(false);
      return {
        xml: '',
        compactXml: '',
        report: { notes: [], skipped: [mapped.message], stats: emptyStats() },
        validation,
      };
    }

    ctx.mappedRoot = mapped.root;
    ctx.report = mapped.report;
    const xml = this.jsonToXML(mapped.root, true, mapped.report);
    const compactXml = this.jsonToXML(mapped.root, false, mapped.report);
    ctx.outputXml = xml;

    const validation = runValidators(ctx);
    this.conversionReport$.next(mapped.report);
    this.validationReport$.next(validation);
    this.conversionAvailable$.next(validation.canDownload);

    return {
      xml: validation.canDownload ? xml : '',
      compactXml: validation.canDownload ? compactXml : '',
      report: mapped.report,
      validation,
    };
  }

  jsonToXML(opnJson: { opnsense: Record<string, unknown> }, pretty?: boolean, report?: ConversionNotes) {
    const shouldPretty = pretty != undefined ? pretty : true;
    const builder = new XMLBuilder({
      ignoreAttributes: false,
      attributeNamePrefix: '@_',
      format: shouldPretty,
      suppressEmptyNode: false,
      commentPropName: '#comment',
    });

    const body = builder.build(opnJson);
    const comment = report
      ? `<!--\n${buildConversionComment(report).replace(/--+/g, '—')}\n-->\n`
      : '';
    const xml = `<?xml version="1.0"?>\n${comment}${body}`;
    if (shouldPretty) {
      return xml;
    }
    return xml.replace(/>\s+</g, '><');
  }
}

function emptyStats() {
  return {
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
  };
}
