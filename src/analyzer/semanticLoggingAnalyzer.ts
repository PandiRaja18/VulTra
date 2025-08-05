import { FeatureExtractionPipeline, pipeline, Pipeline } from '@xenova/transformers';
import { VulnerabilityIssue } from '../types';

export interface SemanticMatch {
    keyword: string;
    similarity: number;
    matchedText: string;
    category: string;
}

export class SemanticLoggingAnalyzer {
    private embeddingPipeline: FeatureExtractionPipeline | null = null;
    private isInitialized = false;
    
    // Sensitive keywords categorized for better analysis
    private readonly SENSITIVE_KEYWORDS = {
        'user_data': ['user', 'customer', 'userdetails', 'profile', 'personal', 'individual'],
        'authentication': ['password', 'secret', 'token', 'auth', 'credential', 'login'],
        'api_security': ['api', 'apikey', 'bearer', 'oauth', 'authorization'],
        'financial': ['payment', 'card', 'account number', 'billing', 'transaction', 'money'],
        'personal_info': ['email', 'phone', 'address', 'ssn', 'social security', 'pii']
    };

    // Logging patterns to detect
    private readonly LOGGING_PATTERNS = [
        /(?:LOGGER|LOG|logger|log)\s*\.\s*(info|debug|warn|error|trace|severe|warning)\s*\(/gi,
        /System\s*\.\s*out\s*\.\s*print(?:ln)?\s*\(/gi,
        /System\s*\.\s*err\s*\.\s*print(?:ln)?\s*\(/gi
    ];

    private readonly SIMILARITY_THRESHOLD = 0.85; // Adjust based on sensitivity needs

    constructor() {
        this.initializeModel();
    }

    private async initializeModel(): Promise<void> {
        try {
            console.log('🤖 Initializing semantic model (Xenova/all-MiniLM-L6-v2)...');
            
            // Initialize the embedding pipeline with the lightweight model
            this.embeddingPipeline = await pipeline(
                'feature-extraction',
                'Xenova/all-MiniLM-L6-v2',
                {
                    // Use local caching to reduce download size
                    cache_dir: './model_cache',
                    // Quantization for smaller model size
                    quantized: true
                }
            );
            
            this.isInitialized = true;
            console.log('✅ Semantic model initialized successfully');
        } catch (error) {
            console.error('❌ Failed to initialize semantic model:', error);
            this.isInitialized = false;
        }
    }

    public async analyzeLoggingStatements(code: string): Promise<VulnerabilityIssue[]> {
        if (!this.isInitialized || !this.embeddingPipeline) {
            console.warn('⚠️ Semantic model not initialized, falling back to keyword matching');
            return this.fallbackKeywordAnalysis(code);
        }

        const issues: VulnerabilityIssue[] = [];
        const lines = code.split('\n');

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            const lineNumber = i + 1;

            // Check if line contains logging
            const hasLogging = this.LOGGING_PATTERNS.some(pattern => pattern.test(line));
            
            if (hasLogging) {
                try {
                    const semanticIssues = await this.analyzeLoggingLine(line, lineNumber);
                    issues.push(...semanticIssues);
                } catch (error) {
                    console.error(`Error analyzing line ${lineNumber}:`, error);
                    // Fall back to keyword matching for this line
                    const fallbackIssues = this.fallbackLineAnalysis(line, lineNumber);
                    issues.push(...fallbackIssues);
                }
            }
        }

        return issues;
    }

    private async analyzeLoggingLine(line: string, lineNumber: number): Promise<VulnerabilityIssue[]> {
        const issues: VulnerabilityIssue[] = [];
        
        // Extract the content being logged (text between quotes and method calls)
        const loggedContent = this.extractLoggedContent(line);
        
        if (loggedContent.length === 0) {
            return issues;
        }

        // Analyze each piece of logged content
        for (const content of loggedContent) {
            const matches = await this.findSemanticMatches(content);
            
            for (const match of matches) {
                if (match.similarity >= this.SIMILARITY_THRESHOLD) {
                    issues.push({
                        lineNumber,
                        description: `Potential sensitive ${match.category} detected in logging: "${match.matchedText}" (similarity: ${(match.similarity * 100).toFixed(1)}%)`,
                        severity: this.getSeverityByCategory(match.category),
                        suggestedFix: this.getSuggestedFix(match.category, match.matchedText),
                        fileName: '',
                        range: null,
                        diagnostic: null,
                        message: "Potential sensitive information detected in logging:"
                    });
                }
            }
        }

        return issues;
    }

    private extractLoggedContent(line: string): string[] {
        const content: string[] = [];
        
        // Extract string literals
        const stringMatches = line.match(/"([^"]+)"|'([^']+)'/g);
        if (stringMatches) {
            content.push(...stringMatches.map(s => s.slice(1, -1))); // Remove quotes
        }
        
        // Extract method calls that might contain sensitive data
        const methodMatches = line.match(/\.\s*get\w+\(\)/gi);
        if (methodMatches) {
            content.push(...methodMatches.map(m => m.replace(/^\.\s*/, ''))); // Remove leading dot
        }
        
        // Extract variable names that might be sensitive
        const variableMatches = line.match(/\b\w*(?:user|customer|pass|secret|token|key|auth|account|payment)\w*\b/gi);
        if (variableMatches) {
            content.push(...variableMatches);
        }

        return content.filter(c => c.length > 2); // Filter out very short strings
    }

    private async findSemanticMatches(text: string): Promise<SemanticMatch[]> {
        if (!this.embeddingPipeline) return [];

        const matches: SemanticMatch[] = [];
        
        try {
            // Get embedding for the text
            const textEmbedding = await this.embeddingPipeline(text, {
                pooling: 'mean',
                normalize: true
            });

            // Compare with each category of sensitive keywords
            for (const [category, keywords] of Object.entries(this.SENSITIVE_KEYWORDS)) {
                for (const keyword of keywords) {
                    try {
                        // Get embedding for the keyword
                        const keywordEmbedding = await this.embeddingPipeline(keyword, {
                            pooling: 'mean',
                            normalize: true
                        });

                        // Calculate cosine similarity
                        const similarity = this.cosineSimilarity(
                            Array.from(textEmbedding.data),
                            Array.from(keywordEmbedding.data)
                        );

                        if (similarity >= this.SIMILARITY_THRESHOLD) {
                            matches.push({
                                keyword,
                                similarity,
                                matchedText: text,
                                category
                            });
                        }
                    } catch (error) {
                        console.error(`Error processing keyword "${keyword}":`, error);
                    }
                }
            }
        } catch (error) {
            console.error('Error in semantic analysis:', error);
        }

        return matches;
    }

    private cosineSimilarity(vecA: number[] | Float32Array, vecB: number[] | Float32Array): number {
        const dotProduct = Array.from(vecA).reduce((sum, a, i) => sum + a * vecB[i], 0);
        const normA = Math.sqrt(Array.from(vecA).reduce((sum, a) => sum + a * a, 0));
        const normB = Math.sqrt(Array.from(vecB).reduce((sum, b) => sum + b * b, 0));
        
        return dotProduct / (normA * normB);
    }

    private getSeverityByCategory(category: string): 'high' | 'medium' | 'low' {
        switch (category) {
            case 'authentication':
            case 'api_security':
                return 'high';
            case 'financial':
            case 'personal_info':
                return 'high';
            case 'user_data':
                return 'medium';
            default:
                return 'medium';
        }
    }

    private getSuggestedFix(category: string, matchedText: string): string {
        switch (category) {
            case 'authentication':
                return `Remove authentication data "${matchedText}" from logging. Never log passwords, tokens, or credentials. Use masked values or omit entirely.`;
            case 'api_security':
                return `Remove API security data "${matchedText}" from logging. Log only non-sensitive request metadata or operation status.`;
            case 'financial':
                return `Remove financial data "${matchedText}" from logging. Log only transaction IDs or sanitized references for compliance.`;
            case 'personal_info':
                return `Remove personal information "${matchedText}" from logging. Use hashed values or user IDs instead of PII.`;
            case 'user_data':
                return `Review user data "${matchedText}" in logging. Consider logging only user IDs or non-sensitive metadata.`;
            default:
                return `Review sensitive data "${matchedText}" in logging statement and remove if it contains confidential information.`;
        }
    }

    // Fallback keyword-based analysis when semantic model fails
    private fallbackKeywordAnalysis(code: string): VulnerabilityIssue[] {
        const issues: VulnerabilityIssue[] = [];
        const lines = code.split('\n');
        
        const allKeywords = Object.values(this.SENSITIVE_KEYWORDS).flat();
        
        lines.forEach((line, index) => {
            const hasLogging = this.LOGGING_PATTERNS.some(pattern => pattern.test(line));
            
            if (hasLogging) {
                const lineIssues = this.fallbackLineAnalysis(line, index + 1);
                issues.push(...lineIssues);
            }
        });

        return issues;
    }

    private fallbackLineAnalysis(line: string, lineNumber: number): VulnerabilityIssue[] {
        const issues: VulnerabilityIssue[] = [];
        const allKeywords = Object.values(this.SENSITIVE_KEYWORDS).flat();
        
        allKeywords.forEach(keyword => {
            const regex = new RegExp(`\\b${keyword}\\b`, 'gi');
            const matches = line.match(regex);
            
            if (matches) {
                matches.forEach(match => {
                    issues.push({
                        lineNumber,
                        description: `Potential sensitive keyword detected in logging: "${match}" (keyword matching)`,
                        severity: 'medium',
                        suggestedFix: `Review and remove sensitive keyword "${match}" from logging statement.`,
                        fileName: '',
                        range: null,
                        diagnostic: null,
                        message: "Potential sensitive information detected in logging:"
                    });
                });
            }
        });

        return issues;
    }

    public async generateSemanticReport(code: string): Promise<string> {
        const issues = await this.analyzeLoggingStatements(code);
        
        let report = '🔍 SEMANTIC LOGGING ANALYSIS REPORT\n';
        report += '='.repeat(50) + '\n\n';
        
        report += `🤖 Model: Xenova/all-MiniLM-L6-v2\n`;
        report += `📊 Similarity Threshold: ${(this.SIMILARITY_THRESHOLD * 100).toFixed(0)}%\n`;
        report += `⚙️  Model Status: ${this.isInitialized ? '✅ Initialized' : '❌ Not Available'}\n\n`;
        
        if (issues.length === 0) {
            report += '✅ No sensitive logging issues detected.\n';
            return report;
        }
        
        const severityCounts = { high: 0, medium: 0, low: 0 };
        issues.forEach(issue => {
            severityCounts[issue.severity]++;
        });
        
        report += `📊 Summary:\n`;
        report += `   Total Issues: ${issues.length}\n`;
        report += `   🔴 High: ${severityCounts.high}\n`;
        report += `   🟡 Medium: ${severityCounts.medium}\n`;
        report += `   🔵 Low: ${severityCounts.low}\n\n`;
        
        report += `🚨 Detailed Issues:\n`;
        issues.forEach((issue, index) => {
            const severityIcon = issue.severity === 'high' ? '🔴' : issue.severity === 'medium' ? '🟡' : '🔵';
            report += `\n${index + 1}. ${severityIcon} Line ${issue.lineNumber}\n`;
            report += `   Description: ${issue.description}\n`;
            report += `   Fix: ${issue.suggestedFix}\n`;
        });
        
        return report;
    }

    public isModelReady(): boolean {
        return this.isInitialized;
    }
}