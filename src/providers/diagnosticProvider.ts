import { VulnerabilityIssue, AnalysisResult } from '../types';

export interface Diagnostic {
    line: number;
    column: number;
    severity: 'error' | 'warning' | 'info';
    message: string;
    source: string;
    code?: string;
}

export class DiagnosticProvider {
    private diagnostics: Map<string, Diagnostic[]> = new Map();

    public provideDiagnostics(fileName: string, issues: VulnerabilityIssue[]): Diagnostic[] {
        const diagnostics = this.convertIssuesToDiagnostics(issues);
        this.diagnostics.set(fileName, diagnostics);
        return diagnostics;
    }

    public getDiagnosticsForFile(fileName: string): Diagnostic[] {
        return this.diagnostics.get(fileName) || [];
    }

    public getAllDiagnostics(): Map<string, Diagnostic[]> {
        return new Map(this.diagnostics);
    }

    private convertIssuesToDiagnostics(issues: VulnerabilityIssue[]): Diagnostic[] {
        return issues.map(issue => ({
            line: issue.lineNumber,
            column: 0,
            severity: this.getSeverity(issue.severity),
            message: issue.description,
            source: 'Java Vulnerability Analyzer',
            code: this.getIssueCode(issue)
        }));
    }

    private getSeverity(severity: string): 'error' | 'warning' | 'info' {
        switch (severity) {
            case 'high': return 'error';
            case 'medium': return 'warning';
            case 'low': return 'info';
            default: return 'warning';
        }
    }

    private getIssueCode(issue: VulnerabilityIssue): string {
        if (issue.description.includes('Constant')) {
            return 'CONST_NAMING';
        } else if (issue.description.includes('nesting')) {
            return 'EXCESSIVE_NESTING';
        } else if (issue.description.includes('hardcoded')) {
            return 'HARDCODED_SENSITIVE';
        }
        return 'GENERAL';
    }

    public updateDiagnostics(fileName: string, issues: VulnerabilityIssue[]): void {
        this.provideDiagnostics(fileName, issues);
        console.log(`📊 Updated diagnostics for ${fileName}: ${issues.length} issue(s)`);
    }

    public clearDiagnostics(fileName?: string): void {
        if (fileName) {
            this.diagnostics.delete(fileName);
            console.log(`🧹 Cleared diagnostics for ${fileName}`);
        } else {
            this.diagnostics.clear();
            console.log('🧹 Cleared all diagnostics');
        }
    }

    public generateDiagnosticReport(): string {
        let report = '🔍 DIAGNOSTIC REPORT\n';
        report += '='.repeat(40) + '\n\n';

        if (this.diagnostics.size === 0) {
            report += 'No diagnostics available.\n';
            return report;
        }

        this.diagnostics.forEach((diagnostics, fileName) => {
            report += `📄 ${fileName}\n`;
            report += '-'.repeat(30) + '\n';

            if (diagnostics.length === 0) {
                report += '  ✅ No issues found\n\n';
                return;
            }

            const severityCounts = { error: 0, warning: 0, info: 0 };
            diagnostics.forEach(diagnostic => {
                severityCounts[diagnostic.severity]++;
            });

            report += `  🔴 Errors: ${severityCounts.error}\n`;
            report += `  🟡 Warnings: ${severityCounts.warning}\n`;
            report += `  🔵 Info: ${severityCounts.info}\n\n`;

            diagnostics.forEach((diagnostic, index) => {
                const icon = this.getSeverityIcon(diagnostic.severity);
                report += `  ${index + 1}. ${icon} Line ${diagnostic.line}: ${diagnostic.message}\n`;
            });

            report += '\n';
        });

        return report;
    }

    private getSeverityIcon(severity: string): string {
        switch (severity) {
            case 'error': return '🔴';
            case 'warning': return '🟡';
            case 'info': return '🔵';
            default: return '⚪';
        }
    }

    public getTotalIssueCount(): number {
        let total = 0;
        this.diagnostics.forEach(diagnostics => {
            total += diagnostics.length;
        });
        return total;
    }

    public getIssueCountBySeverity(): { error: number; warning: number; info: number } {
        const counts = { error: 0, warning: 0, info: 0 };
        
        this.diagnostics.forEach(diagnostics => {
            diagnostics.forEach(diagnostic => {
                counts[diagnostic.severity]++;
            });
        });

        return counts;
    }
}