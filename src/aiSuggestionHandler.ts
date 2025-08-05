import * as vscode from 'vscode';
import { VulnerabilityIssue, AnalysisResult } from './types';
import { VulnerabilityScanner } from './analyzer/vulnerabilityScanner';
import { VulnerabilityPanel } from './providers/vulnerabilityPanel';

interface VulnerabilitySuggestion {
    id: string;
    issueDescription: string;
    suggestedFix: string;
    aiGeneratedCode: string;
    lineNumber: number;
    fileName: string;
    originalCode: string;
}

export class AISuggestionHandler {
    private scanner: VulnerabilityScanner;
    private vulnerabilityPanel: VulnerabilityPanel;
    private static suggestionCache: Map<string, VulnerabilitySuggestion> = new Map();
    
    constructor() {
        this.scanner = new VulnerabilityScanner();
        this.vulnerabilityPanel = VulnerabilityPanel.createOrShow();
    }
    
    /**
     * Generates a unique key for a vulnerability issue
     */
    private getSuggestionKey(vulnerability: VulnerabilityIssue): string {
        return `${vulnerability.fileName}:${vulnerability.lineNumber}:${this.hashString(vulnerability.description)}`;
    }
    
    private hashString(str: string): string {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32bit integer
        }
        return Math.abs(hash).toString();
    }
    
    /**
     * Command handler for applying AI suggestion
     */
    public async applySuggestionCommand(suggestionId: string): Promise<void> {
        try {
            const suggestion = AISuggestionHandler.suggestionCache.get(suggestionId);
            if (!suggestion) {
                vscode.window.showErrorMessage('Suggestion not found. Please generate a new suggestion.');
                return;
            }
            
            console.log(`🔧 Applying AI suggestion for ${suggestion.fileName}:${suggestion.lineNumber}`);
            
            // Apply the suggested code change
            await this.applyCodeChange(suggestion.fileName, suggestion.lineNumber, suggestion.aiGeneratedCode);
            vscode.window.showInformationMessage(`✅ AI security fix applied to line ${suggestion.lineNumber}!`);
            
            // Refresh analysis after applying fix
            setTimeout(() => {
                this.getSuggestionCommand();
            }, 1000);
            
        } catch (error) {
            console.error('❌ Error applying AI suggestion:', error);
            vscode.window.showErrorMessage(`Failed to apply suggestion: ${error}`);
        }
    }
    
    /**
     * Command handler for getting AI suggestions
     */
    public async getSuggestionCommand(): Promise<void> {
        try {
            const activeEditor = vscode.window.activeTextEditor;
            if (!activeEditor) {
                vscode.window.showWarningMessage('No active editor. Please open a Java file.');
                return;
            }
            
            if (activeEditor.document.languageId !== 'java') {
                vscode.window.showWarningMessage('Please open a Java file to get AI suggestions.');
                return;
            }
            
            const fileName = activeEditor.document.fileName;
            console.log(`🔍 Analyzing file for AI suggestions: ${fileName}`);
            
            // Show progress
            vscode.window.showInformationMessage('🤖 Generating AI-powered security suggestions...');
            
            const result = await this.scanner.analyze(activeEditor.document.getText());
            result.fileName = fileName;
            
            if (result.issues.length === 0) {
                vscode.window.showInformationMessage('✅ No security issues found in this file.');
                return;
            }
            
            const suggestions = await this.generateSuggestions(result.issues);
            this.displaySuggestionsInPanel(suggestions);
            
        } catch (error) {
            console.error('❌ Error getting AI suggestions:', error);
            vscode.window.showErrorMessage(`Failed to get suggestions: ${error}`);
        }
    }
    
    /**
     * Generates AI-powered suggestions for vulnerability issues
     */
    public async generateSuggestions(vulnerabilities: VulnerabilityIssue[]): Promise<VulnerabilitySuggestion[]> {
        const suggestions: VulnerabilitySuggestion[] = [];
        
        console.log(`🤖 Generating suggestions for ${vulnerabilities.length} issues`);
        
        for (let i = 0; i < vulnerabilities.length; i++) {
            const vulnerability = vulnerabilities[i];
            const suggestionKey = this.getSuggestionKey(vulnerability);
            
            console.log(`  Processing issue ${i + 1}/${vulnerabilities.length}: Line ${vulnerability.lineNumber}`);
            
            // Check if suggestion is already cached
            if (AISuggestionHandler.suggestionCache.has(suggestionKey)) {
                console.log(`  ✓ Using cached suggestion`);
                suggestions.push(AISuggestionHandler.suggestionCache.get(suggestionKey)!);
                continue;
            }
            
            try {
                // Get original code context
                const originalCode = await this.getCodeContext(vulnerability);
                
                // Since VS Code doesn't have built-in AI, provide rule-based suggestions
                const aiSuggestion = this.generateRuleBasedSuggestion(vulnerability, originalCode);
                
                const suggestion: VulnerabilitySuggestion = {
                    id: suggestionKey,
                    issueDescription: vulnerability.description,
                    suggestedFix: vulnerability.suggestedFix || 'No specific fix provided',
                    aiGeneratedCode: aiSuggestion,
                    lineNumber: vulnerability.lineNumber,
                    fileName: vulnerability.fileName || '',
                    originalCode: originalCode
                };
                
                suggestions.push(suggestion);
                AISuggestionHandler.suggestionCache.set(suggestionKey, suggestion);
                console.log(`  ✅ Suggestion generated`);
                
            } catch (error) {
                console.error(`  ❌ Error generating suggestion:`, error);
                
                // Add a fallback suggestion
                const fallbackSuggestion: VulnerabilitySuggestion = {
                    id: suggestionKey,
                    issueDescription: vulnerability.description,
                    suggestedFix: vulnerability.suggestedFix || 'Manual review required',
                    aiGeneratedCode: `// Suggestion unavailable\n// Please manually fix: ${vulnerability.suggestedFix}`,
                    lineNumber: vulnerability.lineNumber,
                    fileName: vulnerability.fileName || '',
                    originalCode: 'Unable to retrieve original code'
                };
                suggestions.push(fallbackSuggestion);
                AISuggestionHandler.suggestionCache.set(suggestionKey, fallbackSuggestion);
            }
        }
        
        return suggestions;
    }
    
    private generateRuleBasedSuggestion(vulnerability: VulnerabilityIssue, originalCode: string): string {
        // Provide rule-based suggestions based on vulnerability type
        if (vulnerability.description.toLowerCase().includes('sql injection')) {
            return originalCode.replace(/Statement.*executeQuery\([^)]+\)/, 'PreparedStatement pstmt = connection.prepareStatement(sql);\n// Set parameters using pstmt.setString(), pstmt.setInt(), etc.\nResultSet rs = pstmt.executeQuery();');
        }
        
        if (vulnerability.description.toLowerCase().includes('hardcoded')) {
            return '// Use environment variables or configuration files\nString value = System.getenv("SECURE_VALUE");';
        }
        
        if (vulnerability.description.toLowerCase().includes('logging')) {
            return originalCode.replace(/log\.(info|debug|warn|error)\([^)]*\)/, 'log.$1("Sanitized log message without sensitive data");');
        }
        
        return `// Please review and fix the security issue:\n// ${vulnerability.suggestedFix}\n${originalCode}`;
    }
    
    /**
     * Gets code context around the vulnerability
     */
    private async getCodeContext(vulnerability: VulnerabilityIssue): Promise<string> {
        try {
            const activeEditor = vscode.window.activeTextEditor;
            if (!activeEditor) {
                return 'Unable to retrieve code context';
            }
            
            const content = activeEditor.document.getText();
            const lines = content.split('\n');
            
            // Get context: 3 lines before and after the vulnerable line
            const lineIndex = vulnerability.lineNumber - 1;
            const startLine = Math.max(0, lineIndex - 3);
            const endLine = Math.min(lines.length - 1, lineIndex + 3);
            
            const contextLines = lines.slice(startLine, endLine + 1);
            
            return lines[lineIndex] || 'Unable to retrieve vulnerable line';
            
        } catch (error) {
            console.error('Error getting code context:', error);
            return 'Unable to retrieve code context';
        }
    }
    
    /**
     * Displays suggestions in the vulnerability panel with apply buttons
     */
    private displaySuggestionsInPanel(suggestions: VulnerabilitySuggestion[]): void {
        if (suggestions.length === 0) {
            vscode.window.showInformationMessage('No suggestions generated.');
            return;
        }
        
        // Update the vulnerability panel to show suggestions
        this.vulnerabilityPanel.addAISuggestions(suggestions);
        
        console.log(`✅ Generated ${suggestions.length} security suggestions`);
        vscode.window.showInformationMessage(`🤖 Generated ${suggestions.length} security suggestions. Check the vulnerability panel.`);
    }

    /**
     * Applies code change to the specific line in the file
     */
    private async applyCodeChange(fileName: string, lineNumber: number, newCode: string): Promise<void> {
        try {
            const uri = vscode.Uri.file(fileName);
            const document = await vscode.workspace.openTextDocument(uri);
            const editor = await vscode.window.showTextDocument(document);
            
            // Get the range of the line to replace
            const line = lineNumber - 1; // Convert to 0-based index
            const lineText = document.lineAt(line);
            
            const range = new vscode.Range(
                new vscode.Position(line, 0),
                new vscode.Position(line, lineText.text.length)
            );
            
            // Apply the edit
            const edit = new vscode.WorkspaceEdit();
            edit.replace(uri, range, newCode);
        
            const success = await vscode.workspace.applyEdit(edit);
        
            if (!success) {
                throw new Error('Failed to apply edit to document');
            }
            
            // Move cursor to the modified line
            const newPosition = new vscode.Position(line, 0);
            editor.selection = new vscode.Selection(newPosition, newPosition);
            editor.revealRange(new vscode.Range(newPosition, newPosition));
            
            console.log(`✅ Code successfully applied to ${fileName}:${lineNumber}`);
            
        } catch (error) {
            console.error('❌ Error applying code change:', error);
            throw error;
        }
    }
    
    /**
     * Public method to clear suggestion cache
     */
    public clearCache(): void {
        AISuggestionHandler.suggestionCache.clear();
        console.log('🧹 Suggestion cache cleared');
        vscode.window.showInformationMessage('Suggestion cache cleared');
    }
    
    /**
     * Get statistics about cached suggestions
     */
    public getCacheStats(): { count: number; models: string[] } {
        return {
            count: AISuggestionHandler.suggestionCache.size,
            models: []
        };
    }
    
    /**
     * Get a specific suggestion by ID
     */
    public getSuggestion(suggestionId: string): VulnerabilitySuggestion | undefined {
        return AISuggestionHandler.suggestionCache.get(suggestionId);
    }
}