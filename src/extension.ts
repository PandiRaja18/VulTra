import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { VulnerabilityScanner } from './analyzer/vulnerabilityScanner';
import { VulnerabilityPanel } from './providers/vulnerabilityPanel';
import { DiagnosticProvider } from './providers/diagnosticProvider';
import { CodeActionProvider } from './providers/codeActionProvider';
import { AnalysisResult } from './types';

let scanner: VulnerabilityScanner;
let analysisResults: Map<string, AnalysisResult> = new Map();
let vulnerabilityPanel: VulnerabilityPanel;
let diagnosticProvider: DiagnosticProvider;
let codeActionProvider: CodeActionProvider;
let context: vscode.ExtensionContext;

export function activate(extensionContext: vscode.ExtensionContext) {
    console.log('🚀 Java Vulnerability Analyzer is now active!');

    // Store context globally
    context = extensionContext;

    // Initialize components
    scanner = new VulnerabilityScanner();
    vulnerabilityPanel = VulnerabilityPanel.createOrShow();
    vulnerabilityPanel.showResults();
    diagnosticProvider = new DiagnosticProvider();
    codeActionProvider = new CodeActionProvider();

    // Register commands
    // registerCommands();

    // Set up file watchers using VS Code APIs
    setupFileWatchers();

    // Set up document save handler
    setupDocumentSaveHandler();

    console.log('✅ All components initialized successfully');
}

// function registerCommands() {
//     // Register commands using VS Code API
//     const analyzeCommand = vscode.commands.registerCommand(
//         'java-vulnerability-analyzer.analyze',
//         analyzeCurrentFile
//     );

//     const analyzeWorkspaceCommand = vscode.commands.registerCommand(
//         'java-vulnerability-analyzer.analyzeWorkspace',
//         analyzeWorkspace
//     );

//     const showResultsCommand = vscode.commands.registerCommand(
//         'java-vulnerability-analyzer.showResults',
//         showResults
//     );

//     const showDiagnosticsCommand = vscode.commands.registerCommand(
//         'java-vulnerability-analyzer.showDiagnostics',
//         showDiagnostics
//     );

//     const showCodeActionsCommand = vscode.commands.registerCommand(
//         'java-vulnerability-analyzer.showCodeActions',
//         showCodeActions
//     );

//     const analyzeSemanticLoggingCommand = vscode.commands.registerCommand(
//         'java-vulnerability-analyzer.analyzeSemanticLogging',
//         analyzeSemanticLogging
//     );

//     const getAISuggestionCommand = vscode.commands.registerCommand(
//         'java-vulnerability-analyzer.getAISuggestion',
//         getAISuggestions
//     );

//     const applyAIFixCommand = vscode.commands.registerCommand(
//         'java-vulnerability-analyzer.applyAIFix',
//         applyAIFix
//     );

//     // Add to context subscriptions
//     context.subscriptions.push(
//         analyzeCommand,
//         analyzeWorkspaceCommand,
//         showResultsCommand,
//         showDiagnosticsCommand,
//         showCodeActionsCommand,
//         analyzeSemanticLoggingCommand,
//         getAISuggestionCommand,
//         applyAIFixCommand
//     );

//     console.log('📋 VS Code commands registered:');
//     console.log('  - java-vulnerability-analyzer.analyze');
//     console.log('  - java-vulnerability-analyzer.analyzeWorkspace');
//     console.log('  - java-vulnerability-analyzer.showResults');
//     console.log('  - java-vulnerability-analyzer.showDiagnostics');
//     console.log('  - java-vulnerability-analyzer.showCodeActions');
//     console.log('  - java-vulnerability-analyzer.analyzeSemanticLogging');
//     console.log('  - java-vulnerability-analyzer.getAISuggestion');
//     console.log('  - java-vulnerability-analyzer.applyAIFix');
// }

function setupFileWatchers() {
    try {
        // Use VS Code workspace APIs for file watching
        const watcher = vscode.workspace.createFileSystemWatcher('**/*.java');
        
        watcher.onDidChange(async (uri: vscode.Uri): Promise<void> => {
            console.log(`📝 Java file changed: ${path.basename(uri.fsPath)}`);
            await analyzeFile(uri.fsPath);
        });

        watcher.onDidCreate(async (uri: vscode.Uri): Promise<void> => {
            console.log(`➕ Java file added: ${path.basename(uri.fsPath)}`);
            await analyzeFile(uri.fsPath);
        });

        watcher.onDidDelete((uri: vscode.Uri) => {
            console.log(`🗑️ Java file deleted: ${path.basename(uri.fsPath)}`);
            analysisResults.delete(uri.fsPath);
            vulnerabilityPanel.removeResult(uri.fsPath);
            diagnosticProvider.clearDiagnostics(uri.fsPath);
        });

        context.subscriptions.push(watcher);
        console.log('👀 File watcher setup completed');
    } catch (error) {
        console.error('❌ Failed to setup file watcher:', error);
        console.log('📝 File watching may not work properly');
    }
}

function setupDocumentSaveHandler() {
    try {
        // Listen for document save events
        const saveDisposable = vscode.workspace.onDidSaveTextDocument(
            async (document: vscode.TextDocument): Promise<void> => {
                if (document.languageId === 'java') {
                    console.log(`💾 Java file saved: ${path.basename(document.fileName)}`);
                    await analyzeFile(document.fileName);
                }
            }
        );

        context.subscriptions.push(saveDisposable);
        console.log('💾 Document save handler setup completed');
    } catch (error) {
        console.error('❌ Failed to setup document save handler:', error);
        console.log('💾 Auto-analysis on save may not work');
    }
}

async function analyzeFile(filePath: string): Promise<void> {
    try {
        if (!fs.existsSync(filePath)) {
            console.error(`❌ File not found: ${filePath}`);
            return;
        }

        console.log(`🔍 Analyzing: ${path.basename(filePath)}`);
        
        const fileContent = fs.readFileSync(filePath, 'utf-8');
        const analysisResult: AnalysisResult = await scanner.analyze(fileContent);
        analysisResult.fileName = filePath;
        
        // Store results
        analysisResults.set(filePath, analysisResult);
        
        // Update all providers
        vulnerabilityPanel.addResult(analysisResult);
        diagnosticProvider.updateDiagnostics(filePath, analysisResult.issues);
        codeActionProvider.setIssues(analysisResult.issues);
        
        // Show vscode notifications
        if (analysisResult.issues.length > 0) {
            const severityCounts = { high: 0, medium: 0, low: 0 };
            analysisResult.issues.forEach((issue) => {
                severityCounts[issue.severity as keyof typeof severityCounts]++;
            });
            
            // vscode.workbench.showInformationMessage(
            //     `Found ${analysisResult.issues.length} issue(s) in ${path.basename(filePath)} ` +
            //     `(🔴${severityCounts.high} 🟡${severityCounts.medium} 🔵${severityCounts.low})`
            // );
            displayResults(analysisResult);
            vulnerabilityPanel.showResults();
        } else {
            console.log(`✅ No issues found in ${path.basename(filePath)}`);
            vscode.window.showInformationMessage(`✅ No vulnerabilities found in ${path.basename(filePath)}`);
        }
    } catch (error) {
        console.error('❌ Error analyzing file:', error);
        vscode.window.showErrorMessage(`Error analyzing Java file: ${error}`);
    }
}

async function analyzeCurrentFile(): Promise<void> {
    try {
        // Use VS Code API to get active text editor
        const activeEditor = vscode.window.activeTextEditor;
        if (activeEditor && activeEditor.document.languageId === 'java') {
            await analyzeFile(activeEditor.document.fileName);
            vscode.window.showInformationMessage('Java vulnerability analysis completed!');
        } else {
            // Fallback to most recent Java file
            const javaFiles = await findJavaFiles();
            if (javaFiles.length === 0) {
                vscode.window.showWarningMessage('No Java files found in workspace');
                return;
            }

            const mostRecent = javaFiles
                .map(file => ({ file, stats: fs.statSync(file.fsPath) }))
                .sort((a, b) => b.stats.mtime.getTime() - a.stats.mtime.getTime())[0];

            await analyzeFile(mostRecent.file.fsPath);
            vscode.window.showInformationMessage('Current file analysis completed!');
        }
    } catch (error) {
        console.error('❌ Error analyzing current file:', error);
        vscode.window.showErrorMessage(`Error analyzing current file: ${error}`);
    }
}

async function analyzeWorkspace(): Promise<void> {
    try {
        const javaFiles = await findJavaFiles();
        const results: AnalysisResult[] = [];
        
        vscode.window.showInformationMessage(`Found ${javaFiles.length} Java files to analyze...`);
        
        // Show progress using VS Code API
        // await vscode.window.withProgress({
        //     location: vscode.ProgressLocation.Notification,
        //     title: 'Analyzing Java files...',
        //     cancellable: false
        // }, async (progress: vscode.Progress<{ message?: string; increment?: number }>) => {
        //     interface FileStat {
        //     file: vscode.Uri;
        //     stats: fs.Stats;
        //     }

        for (let i: number = 0; i < javaFiles.length; i++) {
            const filePath: vscode.Uri = javaFiles[i]; 
            // javaFiles[i];
            
            console.log(`📄 Processing: ${path.basename(filePath.fsPath)} (${i + 1}/${javaFiles.length})`);
            
            const fileContent: string = fs.readFileSync(filePath.fsPath, 'utf-8');
            const analysisResult: AnalysisResult = await scanner.analyze(fileContent);
            analysisResult.fileName = filePath.fsPath;
            results.push(analysisResult);
            analysisResults.set(filePath.fsPath, analysisResult);
            
            // Show progress via notification messages for every 10 files or at key intervals
            if (i % 10 === 0 || i === javaFiles.length - 1) {
                vscode.window.showInformationMessage(
                    `Analyzing Java files... ${i + 1}/${javaFiles.length} completed`
                );
            }
            
            // Update providers for each file
            diagnosticProvider.updateDiagnostics(filePath.fsPath, analysisResult.issues);
        }

        
        // Update panel with all results
        vulnerabilityPanel.updateResults(results);
        
        const totalIssues = results.reduce((sum, result) => sum + result.issues.length, 0);
        vscode.window.showInformationMessage(
            `Analyzed ${javaFiles.length} Java files. Found ${totalIssues} vulnerability issue(s).`
        );
        
        // Display summary
        displayWorkspaceSummary(results);
        // if (totalIssues > 0) {
        //     vulnerabilityPanel.showResults();
        // }
    } catch (error) {
        console.error('❌ Error analyzing workspace:', error);
        vscode.window.showErrorMessage(`Error analyzing workspace: ${error}`);
    }
}

async function findJavaFiles(): Promise<vscode.Uri[]> {
    try {
        return await vscode.workspace.findFiles('**/*.java', '**/node_modules/**');
    } catch (error) {
        console.error('❌ Error finding Java files:', error);
        const javaFiles: vscode.Uri[] = [];
        
        if (vscode.workspace.workspaceFolders) {
            for (const folder of vscode.workspace.workspaceFolders) {
                const folderPath = folder.uri.fsPath;
                scanDirectory(folderPath, javaFiles);
            }
        }
        
        return javaFiles;
    }
}

function scanDirectory(currentDir: string, javaFiles: vscode.Uri[]): void {
    try {
        const items = fs.readdirSync(currentDir);
        
        for (const item of items) {
            const fullPath = path.join(currentDir, item);
            const stats = fs.statSync(fullPath);
            
            if (stats.isDirectory()) {
                if (!['node_modules', '.git', 'target', 'build', 'out'].includes(item)) {
                    scanDirectory(fullPath, javaFiles);
                }
            } else if (stats.isFile() && item.endsWith('.java')) {
                javaFiles.push(vscode.Uri.file(fullPath));
            }
        }
    } catch (error) {
        console.error(`Error scanning directory ${currentDir}:`, error);
    }
}

function showResults(): void {
    vulnerabilityPanel.showResults();
}

function showDiagnostics(): void {
    const report = diagnosticProvider.generateDiagnosticReport();
    console.log('\n' + report);
    
    const counts = diagnosticProvider.getIssueCountBySeverity();
    const totalIssues = diagnosticProvider.getTotalIssueCount();
    
    if (totalIssues > 0) {
        vscode.window.showInformationMessage(
            `Diagnostics: ${totalIssues} issues (🔴${counts.error} 🟡${counts.warning} 🔵${counts.info})`
        );
    } else {
        vscode.window.showInformationMessage('No diagnostic issues found');
    }
}

function showCodeActions(): void {
    const actions = codeActionProvider.getAllCodeActions();
    
    if (actions.length === 0) {
        console.log('📭 No code actions available');
        vscode.window.showInformationMessage('No code actions available');
        return;
    }
    
    console.log('\n🔧 AVAILABLE CODE ACTIONS');
    console.log('='.repeat(40));
    
    actions.forEach((action, index) => {
        console.log(`${index + 1}. 📄 Line ${action.lineNumber}`);
        console.log(`   🎯 ${action.title}`);
        console.log(`   🔧 ${action.fix}`);
        console.log('');
    });

    vscode.window.showInformationMessage(`Found ${actions.length} code action(s). Check console for details.`);
}

function displayResults(result: AnalysisResult): void {
    const fileName = path.basename(result.fileName);
    
    console.log(`\n📄 ${fileName} (${result.issues.length} issue${result.issues.length !== 1 ? 's' : ''})`);
    console.log('-'.repeat(50));

    result.issues.forEach((issue, index) => {
        const severityIcon = getSeverityIcon(issue.severity);
        console.log(`${index + 1}. ${severityIcon} Line ${issue.lineNumber}: ${issue.description}`);
        if (issue.suggestedFix) {
            console.log(`   💡 ${issue.suggestedFix}`);
        }
        console.log('');
    });
}

function displayWorkspaceSummary(results: AnalysisResult[]): void {
    console.log('\n' + '='.repeat(60));
    console.log('📊 WORKSPACE ANALYSIS SUMMARY');
    console.log('='.repeat(60));

    const severityCounts = { high: 0, medium: 0, low: 0 };
    
    results.forEach(result => {
        result.issues.forEach((issue) => {
            severityCounts[issue.severity as keyof typeof severityCounts]++;
        });
    });

    console.log(`🔴 High Severity: ${severityCounts.high}`);
    console.log(`🟡 Medium Severity: ${severityCounts.medium}`);
    console.log(`🔵 Low Severity: ${severityCounts.low}`);
    console.log('');

    results.forEach(result => {
        if (result.issues.length > 0) {
            const fileName = path.basename(result.fileName);
            console.log(`📄 ${fileName}: ${result.issues.length} issue(s)`);
        }
    });
}

function getSeverityIcon(severity: string): string {
    switch (severity) {
        case 'high': return '🔴';
        case 'medium': return '🟡';
        case 'low': return '🔵';
        default: return '⚪';
    }
}

// async function analyzeSemanticLogging(): Promise<void> {
//     try {
//         const activeEditor = vscode.workspace.activeTextEditor;
//         if (activeEditor && activeEditor.document.languageId === 'java') {
//             const fileContent = activeEditor.document.getText();
            
//             vscode.workbench.showInformationMessage('🤖 Running semantic analysis on logging statements...');
            
//             const report = await scanner.generateSemanticLoggingReport(fileContent);
//             console.log('\n' + report);
            
//             const modelStatus = scanner.isSemanticModelReady() ? 'AI model' : 'keyword matching';
//             vscode.workbench.showInformationMessage(`Semantic logging analysis completed using ${modelStatus}. Check console for details.`);
//         } else {
//             vscode.workbench.showWarningMessage('Please open a Java file to analyze semantic logging.');
//         }
//     } catch (error) {
//         console.error('❌ Error in semantic logging analysis:', error);
//         vscode.workbench.showErrorMessage(`Error in semantic analysis: ${error}`);
//     }
// }

// async function getAISuggestions(): Promise<void> {
//     try {
//         const { AISuggestionHandler } = await import('./aiSuggestionHandler');
//         const aiHandler = new AISuggestionHandler();
//         await aiHandler.getSuggestionCommand();
//     } catch (error) {
//         console.error('❌ Error getting AI suggestions:', error);
//         vscode.workbench.showErrorMessage(`Failed to get AI suggestions: ${error}`);
//     }
// }

// async function applyAIFix(suggestionId: string): Promise<void> {
//     try {
//         const { AISuggestionHandler } = await import('./aiSuggestionHandler');
//         const aiHandler = new AISuggestionHandler();
//         await aiHandler.applySuggestionCommand(suggestionId);
//     } catch (error) {
//         console.error('❌ Error applying AI fix:', error);
//         vscode.workbench.showErrorMessage(`Failed to apply AI fix: ${error}`);
//     }
// }

export function deactivate() {
    console.log('🛑 Java Vulnerability Analyzer deactivated');
    
    if (vulnerabilityPanel) {
        vulnerabilityPanel.dispose();
    }
    
    analysisResults.clear();
}