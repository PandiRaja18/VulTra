export interface VulnerabilityIssue {
    fileName: string;
    lineNumber: number;
    description: string;
    severity: 'low' | 'medium' | 'high';
    // Add missing properties for CodeActionProvider
    message: string;
    range: any;
    suggestedFix: string;
    diagnostic: any;
}
export interface AnalysisResult {
    fileName: string; // Add missing fileName property
    issues: VulnerabilityIssue[];
    totalIssues?: number;
    timestamp?: Date;
}

export interface SecurityPattern {
    name: string;
    pattern: RegExp;
    severity: 'high' | 'medium' | 'low';
    description: string;
    suggestedFix: string;
}