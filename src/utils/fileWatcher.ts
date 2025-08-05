import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { VulnerabilityScanner } from '../analyzer/vulnerabilityScanner';

export class FileWatcher {
    private watcher: vscode.FileSystemWatcher;
    private scanner: VulnerabilityScanner;
    private onAnalysisComplete?: (uri: vscode.Uri) => void;

    constructor(onAnalysisComplete?: (uri: vscode.Uri) => void) {
        this.scanner = new VulnerabilityScanner();
        this.onAnalysisComplete = onAnalysisComplete;
        this.watcher = vscode.workspace.createFileSystemWatcher('**/*.java');

        // Use onDidChange instead of onDidSave
        this.watcher.onDidChange((uri: vscode.Uri) => {
            this.triggerAnalysisForUri(uri);
        });

        this.watcher.onDidCreate((uri: vscode.Uri) => {
            this.triggerAnalysisForUri(uri);
        });
    }

    private async triggerAnalysisForUri(uri: vscode.Uri): Promise<void> {
        try {
            await this.scanner.analyzeFile(uri.fsPath);
            if (this.onAnalysisComplete) {
                this.onAnalysisComplete(uri);
            }
        } catch (error) {
            console.error('Error analyzing file:', error);
        }
    }

    public async triggerAnalysisForDocument(document: vscode.TextDocument): Promise<void> {
        if (document.languageId === 'java') {
            try {
                const result = this.scanner.analyze(document.getText());
                (await result).fileName = document.fileName;
                
                if (this.onAnalysisComplete) {
                    this.onAnalysisComplete(document.uri);
                }
            } catch (error) {
                console.error('Error analyzing document:', error);
            }
        }
    }

    public async analyzeWorkspace(): Promise<number> {
        try {
            const workspaceFolders = vscode.workspace.workspaceFolders;
            if (!workspaceFolders) {
                return 0;
            }
            
            let totalFiles = 0;
            for (const folder of workspaceFolders) {
                const javaFiles = this.findJavaFiles(folder.uri.fsPath);
                
                for (const filePath of javaFiles) {
                    const fileUri = vscode.Uri.file(filePath);
                    await this.triggerAnalysisForUri(fileUri);
                }
                
                totalFiles += javaFiles.length;
            }
            
            return totalFiles;
        } catch (error) {
            console.error('Error analyzing workspace:', error);
            return 0;
        }
    }

    private findJavaFiles(dir: string): string[] {
        const javaFiles: string[] = [];
        
        function scanDirectory(currentDir: string): void {
            try {
                const items = fs.readdirSync(currentDir);
                
                for (const item of items) {
                    const fullPath = path.join(currentDir, item);
                    
                    try {
                        const stats = fs.statSync(fullPath);
                        
                        if (stats.isDirectory()) {
                            // Skip common build/dependency directories
                            if (!['node_modules', '.git', 'target', 'build', 'out', '.idea', '.vscode'].includes(item)) {
                                scanDirectory(fullPath);
                            }
                        } else if (stats.isFile() && item.endsWith('.java')) {
                            javaFiles.push(fullPath);
                        }
                    } catch (statError) {
                        console.warn(`⚠️ Cannot access ${fullPath}:`, statError);
                    }
                }
            } catch (readError) {
                console.warn(`⚠️ Cannot read directory ${currentDir}:`, readError);
            }
        }
        
        scanDirectory(dir);
        return javaFiles;
    }


    public dispose(): void {
        this.watcher.dispose();
    }
}