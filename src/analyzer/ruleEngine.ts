import * as fs from 'fs';
import * as path from 'path';

export interface Rule {
    id: string;
    name: string;
    description: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    pattern?: string;
    enabled: boolean;
}

export interface RuleSet {
    version: string;
    rules: Rule[];
}

export class RuleEngine {
    private rules!: RuleSet;

    constructor() {
        this.loadRules();
    }

    private loadRules() {
        try {
            const rulesPath = path.join(__dirname, '../../resources/rules/vulnerability-rules.json');
            
            // Check if rules file exists, if not create default rules
            if (!fs.existsSync(rulesPath)) {
                this.createDefaultRules(rulesPath);
            }
            
            const rulesContent = fs.readFileSync(rulesPath, 'utf-8');
            this.rules = JSON.parse(rulesContent);
        } catch (error) {
            console.warn('Failed to load rules file, using default rules:', error);
            this.rules = this.getDefaultRules();
        }
    }

    private createDefaultRules(rulesPath: string) {
        const defaultRules = this.getDefaultRules();
        
        // Ensure directory exists
        const rulesDir = path.dirname(rulesPath);
        if (!fs.existsSync(rulesDir)) {
            fs.mkdirSync(rulesDir, { recursive: true });
        }
        
        fs.writeFileSync(rulesPath, JSON.stringify(defaultRules, null, 2));
    }

    private getDefaultRules(): RuleSet {
        return {
            version: "1.0.0",
            rules: [
                {
                    id: "naming-convention",
                    name: "Constant Naming Convention",
                    description: "Static final variables should be in UPPER_CASE_WITH_UNDERSCORES",
                    severity: "medium",
                    pattern: "static\\s+final\\s+\\w+\\s+([a-z][A-Za-z0-9_]*)",
                    enabled: true
                },
                {
                    id: "excessive-nesting",
                    name: "Excessive Nesting",
                    description: "Control structures should not be nested more than 4 levels deep",
                    severity: "high",
                    enabled: true
                },
                {
                    id: "hardcoded-sensitive-info",
                    name: "Hardcoded Sensitive Information",
                    description: "API keys, passwords, and secrets should not be hardcoded",
                    severity: "critical",
                    pattern: "(?:api[_-]?key|apikey|secret|password|pwd|token)\\s*=\\s*[\"']([^\"']{8,})[\"']",
                    enabled: true
                }
            ]
        };
    }

    public applyRules(code: string): any[] {
        const issues: any[] = [];
        
        this.rules.rules.forEach(rule => {
            if (rule.enabled && rule.pattern) {
                const regex = new RegExp(rule.pattern, 'gi');
                const lines = code.split('\n');
                
                lines.forEach((line, index) => {
                    let match;
                    while ((match = regex.exec(line)) !== null) {
                        issues.push({
                            ruleId: rule.id,
                            line: index + 1,
                            description: rule.description,
                            severity: rule.severity,
                            match: match[0]
                        });
                    }
                });
            }
        });
        
        return issues;
    }

    public getRules() {
        return this.rules;
    }

    public getRule(id: string): Rule | undefined {
        return this.rules.rules.find(rule => rule.id === id);
    }
}