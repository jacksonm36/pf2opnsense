import { Component, ElementRef, OnDestroy, OnInit, ViewChild } from '@angular/core';
import { ProgressBarMode } from '@angular/material/progress-bar';
import { Subscription } from 'rxjs';
import { ConverterService } from '../services/converter.service';
import { CheckGroup, CheckResult, CheckStatus, ValidationReport } from '../services/validation.types';

@Component({
  selector: 'app-upload',
  templateUrl: './upload.component.html',
  styleUrls: ['./upload.component.scss']
})
export class UploadComponent implements OnInit, OnDestroy {

  @ViewChild('fileUpload') fileUpload?: ElementRef<HTMLInputElement>;

  displayConversionCard: Boolean;
  conversionAvailable: Boolean;
  progressMode: ProgressBarMode = 'indeterminate';
  progressValue: number = 0;
  progressColor: string = 'accent';

  fileName = '';
  unsupportedFile = false;
  renderedXML: string = '';
  renderedNotPrettyXML: string = '';
  conversionNotes: string[] = [];
  visibleChecks: CheckResult[] = [];
  validation: ValidationReport | null = null;
  checksRunning = false;
  showXmlPreview = false;
  acknowledgedWarnings = false;

  private staggerTimers: number[] = [];
  private subscriptions = new Subscription();

  constructor(private converterService: ConverterService) {
    this.displayConversionCard = this.converterService.displayConversionCard$.getValue();
    this.conversionAvailable = this.converterService.conversionAvailable$.getValue();
  }

  get inputChecks(): CheckResult[] {
    return this.visibleChecks.filter((check) => check.group === 'input');
  }

  get convertChecks(): CheckResult[] {
    return this.visibleChecks.filter((check) => check.group === 'convert');
  }

  get outputChecks(): CheckResult[] {
    return this.visibleChecks.filter((check) => check.group === 'output');
  }

  get canDownload(): boolean {
    return !!this.validation?.canDownload && !!this.renderedXML && !this.checksRunning;
  }

  get downloadBlockedByWarnings(): boolean {
    return !!this.validation && this.validation.warnings > 0 && !this.acknowledgedWarnings;
  }

  groupLabel(group: CheckGroup): string {
    if (group === 'input') {
      return '1. Source backup';
    }
    if (group === 'convert') {
      return '2. Conversion';
    }
    return '3. OPNsense 26.7 output';
  }

  statusIcon(status: CheckStatus): string {
    if (status === 'pass') {
      return 'check_circle';
    }
    if (status === 'warn') {
      return 'warning';
    }
    if (status === 'fail') {
      return 'cancel';
    }
    if (status === 'running') {
      return 'hourglass_empty';
    }
    if (status === 'skip') {
      return 'remove_circle_outline';
    }
    return 'radio_button_unchecked';
  }

  reset() {
    this.clearStagger();
    this.fileName = '';
    this.unsupportedFile = false;
    this.progressMode = 'indeterminate';
    this.conversionNotes = [];
    this.visibleChecks = [];
    this.validation = null;
    this.renderedXML = '';
    this.renderedNotPrettyXML = '';
    this.checksRunning = false;
    this.showXmlPreview = false;
    this.acknowledgedWarnings = false;
    this.progressColor = 'accent';
    this.progressValue = 0;
    if (this.fileUpload) {
      this.fileUpload.nativeElement.value = '';
    }
    this.converterService.cancel();
  }

  download() {
    if (!this.canDownload || this.downloadBlockedByWarnings) {
      return;
    }
    this.triggerDownload(this.renderedXML, 'pf2opn-generated-opnsense-config.xml');
  }

  downloadNoPretty() {
    if (!this.canDownload || this.downloadBlockedByWarnings) {
      return;
    }
    this.triggerDownload(this.renderedNotPrettyXML, 'unformatted-pf2opn-generated-opnsense-config.xml');
  }

  private triggerDownload(content: string, filename: string) {
    const element = document.createElement('a');
    element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(content));
    element.setAttribute('download', filename);
    element.style.display = 'none';
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  }

  async onFileSelected(event: Event) {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) {
      return;
    }
    this.clearStagger();
    this.fileName = file.name;
    this.progressColor = 'accent';
    this.visibleChecks = [];
    this.validation = null;
    this.renderedXML = '';
    this.renderedNotPrettyXML = '';
    this.acknowledgedWarnings = false;
    this.showXmlPreview = false;
    this.progressMode = 'indeterminate';
    this.progressValue = 0;

    if (file.type.match('text/xml') || file.name.toLowerCase().endsWith('.xml')) {
      this.unsupportedFile = false;
      this.checksRunning = true;

      (await this.converterService.convert(file)).subscribe({
        next: (res) => {
          this.conversionNotes = [...res.report.notes, ...res.report.skipped];
          this.progressColor = res.validation.errors ? 'warn' : 'accent';
          this.staggerChecks(res.validation, res.xml, res.compactXml);
        },
        error: (err) => {
          this.checksRunning = false;
          this.renderedXML = '';
          this.progressColor = 'warn';
          this.progressMode = 'determinate';
          this.progressValue = 100;
          console.error('conversion failed', err);
        },
      });
    } else {
      this.unsupportedFile = true;
      this.converterService.cancel();
    }
  }

  private staggerChecks(report: ValidationReport, xml: string, compactXml: string) {
    if (!report.checks.length) {
      this.validation = report;
      this.checksRunning = false;
      this.progressMode = 'determinate';
      this.progressValue = 100;
      return;
    }

    this.visibleChecks = report.checks.map((check) => ({ ...check, status: 'pending' as CheckStatus, detail: '' }));
    this.progressMode = 'determinate';
    this.progressValue = 0;

    report.checks.forEach((check, index) => {
      const start = window.setTimeout(() => {
        this.visibleChecks[index] = { ...check, status: 'running', detail: 'Running…' };
        this.visibleChecks = [...this.visibleChecks];
      }, index * 90);
      const finish = window.setTimeout(() => {
        this.visibleChecks[index] = check;
        this.visibleChecks = [...this.visibleChecks];
        this.progressValue = Math.round(((index + 1) / report.checks.length) * 100);
        if (index === report.checks.length - 1) {
          this.validation = report;
          this.checksRunning = false;
          if (report.canDownload) {
            this.renderedXML = xml;
            this.renderedNotPrettyXML = compactXml;
          }
        }
      }, index * 90 + 70);
      this.staggerTimers.push(start, finish);
    });
  }

  private clearStagger() {
    this.staggerTimers.forEach((id) => window.clearTimeout(id));
    this.staggerTimers = [];
  }

  ngOnInit() {
    this.subscriptions.add(
      this.converterService.displayConversionCard$.subscribe((e) => {
        this.displayConversionCard = e;
      })
    );
    this.subscriptions.add(
      this.converterService.conversionAvailable$.subscribe((e) => {
        this.conversionAvailable = e;
      })
    );
  }

  ngOnDestroy() {
    this.clearStagger();
    this.subscriptions.unsubscribe();
  }

}
