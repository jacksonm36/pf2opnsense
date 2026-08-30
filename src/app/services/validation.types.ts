export type CheckStatus = 'pending' | 'running' | 'pass' | 'warn' | 'fail' | 'skip';

export type CheckGroup = 'input' | 'convert' | 'output';

export interface CheckResult {
  id: string;
  group: CheckGroup;
  title: string;
  status: CheckStatus;
  detail: string;
}

export interface ValidationReport {
  checks: CheckResult[];
  passed: number;
  warnings: number;
  errors: number;
  skipped: number;
  canDownload: boolean;
}

export function summarizeChecks(checks: CheckResult[]): ValidationReport {
  const passed = checks.filter((check) => check.status === 'pass').length;
  const warnings = checks.filter((check) => check.status === 'warn').length;
  const errors = checks.filter((check) => check.status === 'fail').length;
  const skipped = checks.filter((check) => check.status === 'skip').length;
  return {
    checks,
    passed,
    warnings,
    errors,
    skipped,
    canDownload: errors === 0 && checks.length > 0,
  };
}
