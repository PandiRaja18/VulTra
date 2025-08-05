import * as vscode from 'vscode';
import { VulnerabilityIssue, AnalysisResult } from '../types';

export class ReportGenerator {
    private findings: Map<string, Array<{ line: number; description: string }>>;

    constructor() {
        this.findings = new Map();
    }

    public addFinding(filename: string, line: number, description: string): void {
        if (!this.findings.has(filename)) {
            this.findings.set(filename, []);
        }
        this.findings.get(filename)?.push({ line, description });
    }

    public generateDiagnostics(analysisResult: AnalysisResult): vscode.Diagnostic[] {
        const diagnostics: vscode.Diagnostic[] = [];
        
        analysisResult.issues.forEach(issue => {
            const range = new vscode.Range(
                new vscode.Position(Math.max(0, issue.lineNumber - 1), 0),
                new vscode.Position(Math.max(0, issue.lineNumber - 1), Number.MAX_VALUE)
            );
            
            const severity = this.getSeverity(issue.severity);
            const diagnostic = new vscode.Diagnostic(range, issue.description, severity);
            diagnostic.source = 'Java Vulnerability Analyzer';
            diagnostics.push(diagnostic);
        });

        return diagnostics;
    }

    public getIssuesForDocument(document: vscode.TextDocument): VulnerabilityIssue[] {
        // This should return issues for the specific document
        // For now, return empty array - implement based on your needs
        return [];
    }

    private getSeverity(severity: string): vscode.DiagnosticSeverity {
        switch (severity) {
            case 'high':
                return vscode.DiagnosticSeverity.Error;
            case 'medium':
                return vscode.DiagnosticSeverity.Warning;
            case 'low':
                return vscode.DiagnosticSeverity.Information;
            default:
                return vscode.DiagnosticSeverity.Warning;
        }
    }

    public generateReport(): string {
        let report = 'Vulnerability Analysis Report\n\n';
        this.findings.forEach((issues, filename) => {
            report += `File: ${filename}\n`;
            issues.forEach(issue => {
                report += `  Line ${issue.line}: ${issue.description}\n`;
            });
            report += '\n';
        });
        return report;
    }

    public clearFindings(): void {
        this.findings.clear();
    }
}