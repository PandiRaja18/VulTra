import { VulnerabilityIssue } from '../types';

export interface CodeAction {
    title: string;
    description: string;
    fix: string;
    lineNumber: number;
    fileName: string;
}

export class CodeActionProvider {
    private issues: VulnerabilityIssue[] = [];

    public setIssues(issues: VulnerabilityIssue[]): void {
        this.issues = issues;
        console.log(`🔧 Code action provider updated with ${issues.length} issues`);
    }

    public getCodeActions(lineNumber: number): CodeAction[] {
        const actionsForLine = this.issues
            .filter(issue => issue.lineNumber === lineNumber)
            .map(issue => this.createCodeAction(issue));

        return actionsForLine;
    }

    public getAllCodeActions(): CodeAction[] {
        return this.issues.map(issue => this.createCodeAction(issue));
    }

    private createCodeAction(issue: VulnerabilityIssue): CodeAction {
        return {
            title: `Fix: ${issue.description}`,
            description: issue.suggestedFix || 'No specific fix available',
            fix: this.generateFix(issue),
            lineNumber: issue.lineNumber,
            fileName: issue.fileName || 'Unknown'
        };
    }

    private generateFix(issue: VulnerabilityIssue): string {
        // Generate specific fixes based on issue type
        if (issue.description.includes('Constant')) {
            return this.generateConstantNamingFix(issue);
        } else if (issue.description.includes('nesting')) {
            return this.generateNestingFix(issue);
        } else if (issue.description.includes('hardcoded')) {
            return this.generateHardcodedFix(issue);
        } else if (issue.description.includes('SQL injection')) {
            return this.generateSQLInjectionFix(issue);
        } else if (issue.description.includes('XSS')) {
            return this.generateXSSFix(issue);
        }

        return issue.suggestedFix || 'Manual review required';
    }

    private generateConstantNamingFix(issue: VulnerabilityIssue): string {
        const match = issue.description.match(/Constant '(\w+)'/);
        if (match) {
            const constantName = match[1];
            const fixedName = constantName.toUpperCase().replace(/([a-z])([A-Z])/g, '$1_$2');
            return `Rename '${constantName}' to '${fixedName}'`;
        }
        return 'Convert to UPPER_CASE_WITH_UNDERSCORES format';
    }

    private generateNestingFix(issue: VulnerabilityIssue): string {
        return 'Consider refactoring this code block:\n' +
               '- Extract methods for complex logic\n' +
               '- Use early returns to reduce nesting\n' +
               '- Consider using guard clauses\n' +
               '- Break down complex conditions';
    }

    private generateHardcodedFix(issue: VulnerabilityIssue): string {
        return 'Move sensitive data to:\n' +
               '- Configuration files (application.properties)\n' +
               '- Environment variables\n' +
               '- Secure key management systems\n' +
               '- External configuration services';
    }

    private generateSQLInjectionFix(issue: VulnerabilityIssue): string {
        return 'Fix SQL injection vulnerability:\n' +
               '- Use PreparedStatement instead of Statement\n' +
               '- Use parameterized queries\n' +
               '- Validate and sanitize user input\n' +
               '- Use ORM frameworks like Hibernate';
    }

    private generateXSSFix(issue: VulnerabilityIssue): string {
        return 'Fix XSS vulnerability:\n' +
               '- Escape output using OWASP Java Encoder\n' +
               '- Use Content Security Policy (CSP)\n' +
               '- Validate and sanitize user input\n' +
               '- Use framework-specific escaping functions';
    }

    public generateFixReport(): string {
        if (this.issues.length === 0) {
            return 'No issues found that require fixes.';
        }

        let report = '📋 CODE FIX SUGGESTIONS\n';
        report += '='.repeat(50) + '\n\n';

        this.issues.forEach((issue, index) => {
            const action = this.createCodeAction(issue);
            report += `${index + 1}. 📄 Line ${issue.lineNumber}\n`;
            report += `   🔍 Issue: ${issue.description}\n`;
            report += `   🔧 Fix: ${action.fix}\n\n`;
        });

        return report;
    }

    public applyAutomaticFixes(sourceCode: string): string {
        let fixedCode = sourceCode;
        
        // Apply automatic fixes for naming conventions
        this.issues.forEach(issue => {
            if (issue.description.includes('Constant')) {
                fixedCode = this.applyConstantNamingFix(fixedCode, issue);
            }
        });

        return fixedCode;
    }

    private applyConstantNamingFix(sourceCode: string, issue: VulnerabilityIssue): string {
        const match = issue.description.match(/Constant '(\w+)'/);
        if (match) {
            const oldName = match[1];
            const newName = oldName.toUpperCase().replace(/([a-z])([A-Z])/g, '$1_$2');
            
            // Replace all occurrences of the constant name
            const regex = new RegExp(`\\b${oldName}\\b`, 'g');
            return sourceCode.replace(regex, newName);
        }
        
        return sourceCode;
    }

    public clear(): void {
        this.issues = [];
        console.log('🧹 Code action provider cleared');
    }
}