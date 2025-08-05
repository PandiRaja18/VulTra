import { VulnerabilityIssue } from '../types';

export interface SensitivePattern {
    pattern: RegExp;
    description: string;
    severity: 'high' | 'medium' | 'low';
    category: string;
}

export class LoggingSensitivityChecker {
    private sensitiveMethodPatterns: SensitivePattern[] = [
        // Customer/User Data Methods
        { 
            pattern: /\.get(Customer|User|Personal|Profile|Account)Data\(\)/gi,
            description: "Customer/user data is being logged - potential PII exposure",
            severity: 'high',
            category: 'PII'
        },
        { 
            pattern: /\.get(Customer|User|Client)(Info|Information|Details)\(\)/gi,
            description: "Customer information is being logged - potential PII exposure",
            severity: 'high',
            category: 'PII'
        },
        
        // Password Related
        { 
            pattern: /\.get(Password|Pass|Pwd|Secret|Token|Key)\(\)/gi,
            description: "Password/secret data is being logged - security risk",
            severity: 'high',
            category: 'Credentials'
        },
        { 
            pattern: /\.(password|pass|pwd|secret|token|key)\b/gi,
            description: "Sensitive credential field is being logged",
            severity: 'high',
            category: 'Credentials'
        },
        
        // API Keys and Tokens
        { 
            pattern: /\.get(Api|API)(Key|Token|Secret)\(\)/gi,
            description: "API key/token is being logged - security risk",
            severity: 'high',
            category: 'API_Credentials'
        },
        { 
            pattern: /\.(apiKey|apiToken|accessToken|authToken|bearerToken)\b/gi,
            description: "API credentials are being logged",
            severity: 'high',
            category: 'API_Credentials'
        },
        
        // Personal Information
        { 
            pattern: /\.get(SSN|SocialSecurity|CreditCard|Email|Phone|Address)\(\)/gi,
            description: "Personal identifiable information (PII) is being logged",
            severity: 'high',
            category: 'PII'
        },
        { 
            pattern: /\.(ssn|socialSecurity|creditCard|email|phone|address|firstName|lastName)\b/gi,
            description: "PII field is being logged",
            severity: 'medium',
            category: 'PII'
        },
        
        // Financial Data
        { 
            pattern: /\.get(Account|Bank|Card|Payment)(Number|Info|Data|Details)\(\)/gi,
            description: "Financial information is being logged - compliance risk",
            severity: 'high',
            category: 'Financial'
        },
        
        // Session Data
        { 
            pattern: /\.get(Session|Cookie|Auth)(Id|Data|Info)\(\)/gi,
            description: "Session/authentication data is being logged",
            severity: 'medium',
            category: 'Session'
        },
        
        // Generic sensitive data patterns
        { 
            pattern: /\.getData\(\)/gi,
            description: "Generic data method is being logged - review for sensitive content",
            severity: 'low',
            category: 'Generic'
        }
    ];

    private loggerPatterns = [
        /LOGGER\.(info|debug|warn|error|trace)\s*\(/gi,
        /LOG\.(info|debug|warn|error|trace)\s*\(/gi,
        /logger\.(info|debug|warn|error|trace)\s*\(/gi,
        /log\.(info|debug|warn|error|trace)\s*\(/gi,
        /System\.out\.print(ln)?\s*\(/gi,
        /System\.err\.print(ln)?\s*\(/gi
    ];

    public checkLoggingSensitivity(code: string): VulnerabilityIssue[] {
        const issues: VulnerabilityIssue[] = [];
        const lines = code.split('\n');

        lines.forEach((line, index) => {
            const lineNumber = index + 1;
            
            // Check if this line contains logging
            const hasLogging = this.loggerPatterns.some(pattern => pattern.test(line));
            
            if (hasLogging) {
                // Check for sensitive patterns in the logging statement
                const sensitiveIssues = this.checkSensitivePatterns(line, lineNumber);
                issues.push(...sensitiveIssues);
            }
        });

        return issues;
    }

    private checkSensitivePatterns(line: string, lineNumber: number): VulnerabilityIssue[] {
        const issues: VulnerabilityIssue[] = [];

        this.sensitiveMethodPatterns.forEach(pattern => {
            const matches = line.match(pattern.pattern);
            if (matches) {
                matches.forEach(match => {
                    const issue: VulnerabilityIssue = {
                        lineNumber,
                        description: `${pattern.description}: "${match}"`,
                        severity: pattern.severity,
                        suggestedFix: this.generateSuggestedFix(pattern.category, match),
                        fileName: '',
                        message: `Sensitive data is been exposed in log`,
                        range: null,
                        diagnostic: null
                    };
                    issues.push(issue);
                });
            }
        });

        return issues;
    }

    private generateSuggestedFix(category: string, matchedPattern: string): string {
        switch (category) {
            case 'PII':
                return `Remove PII logging. Consider logging only non-sensitive identifiers like user ID or hashed values. Replace "${matchedPattern}" with sanitized data.`;
            
            case 'Credentials':
                return `Never log passwords or secrets. Remove "${matchedPattern}" from log statement. Use masked values like "***" for debugging if necessary.`;
            
            case 'API_Credentials':
                return `API keys should never be logged. Remove "${matchedPattern}" and consider logging only the first/last few characters for debugging.`;
            
            case 'Financial':
                return `Financial data logging violates compliance standards. Remove "${matchedPattern}" and log only transaction IDs or sanitized references.`;
            
            case 'Session':
                return `Session data can be used for session hijacking. Remove "${matchedPattern}" and log only session status or sanitized session info.`;
            
            case 'Generic':
                return `Review the content of "${matchedPattern}" to ensure no sensitive data is logged. Consider creating specific non-sensitive logging methods.`;
            
            default:
                return `Review and remove sensitive data from logging statement containing "${matchedPattern}".`;
        }
    }

    public analyzeSensitiveLogging(code: string): {
        totalIssues: number;
        issuesByCategory: Map<string, number>;
        issuesBySeverity: Map<string, number>;
        issues: VulnerabilityIssue[];
    } {
        const issues = this.checkLoggingSensitivity(code);
        const issuesByCategory = new Map<string, number>();
        const issuesBySeverity = new Map<string, number>();

        issues.forEach(issue => {
            // Count by category (extract from description)
            const categoryMatch = issue.description.match(/^(.*?):/);
            const category = categoryMatch ? categoryMatch[1] : 'Unknown';
            issuesByCategory.set(category, (issuesByCategory.get(category) || 0) + 1);
            
            // Count by severity
            issuesBySeverity.set(issue.severity, (issuesBySeverity.get(issue.severity) || 0) + 1);
        });

        return {
            totalIssues: issues.length,
            issuesByCategory,
            issuesBySeverity,
            issues
        };
    }

    public generateDetailedReport(code: string): string {
        const analysis = this.analyzeSensitiveLogging(code);
        
        let report = '🔒 LOGGING SENSITIVITY ANALYSIS REPORT\n';
        report += '='.repeat(50) + '\n\n';
        
        report += `📊 Summary:\n`;
        report += `   Total Issues: ${analysis.totalIssues}\n`;
        
        if (analysis.issuesBySeverity.size > 0) {
            report += `   By Severity:\n`;
            analysis.issuesBySeverity.forEach((count, severity) => {
                const icon = severity === 'high' ? '🔴' : severity === 'medium' ? '🟡' : '🔵';
                report += `     ${icon} ${severity.toUpperCase()}: ${count}\n`;
            });
        }
        
        if (analysis.issuesByCategory.size > 0) {
            report += `   By Category:\n`;
            analysis.issuesByCategory.forEach((count, category) => {
                report += `     📂 ${category}: ${count}\n`;
            });
        }
        
        if (analysis.issues.length > 0) {
            report += `\n🚨 Detailed Issues:\n`;
            analysis.issues.forEach((issue, index) => {
                const severityIcon = issue.severity === 'high' ? '🔴' : issue.severity === 'medium' ? '🟡' : '🔵';
                report += `\n${index + 1}. ${severityIcon} Line ${issue.lineNumber}\n`;
                report += `   Description: ${issue.description}\n`;
                report += `   Fix: ${issue.suggestedFix}\n`;
            });
        }
        
        return report;
    }
}