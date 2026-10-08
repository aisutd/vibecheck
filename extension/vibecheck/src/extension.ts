// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';

// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed
export function activate(context: vscode.ExtensionContext) {

	// Use the console to output diagnostic information (console.log) and errors (console.error)
	// This line of code will only be executed once when your extension is activated
	console.log('Congratulations, your extension "vibecheck" is now active!');

	// The command has been defined in the package.json file
	// Now provide the implementation of the command with registerCommand
	// The commandId parameter must match the command field in package.json
	const disposable = vscode.commands.registerCommand('vibecheck.helloWorld', () => {
		// The code you place here will be executed every time your command is executed
		// Display a message box to the user
		vscode.window.showInformationMessage('Hello World from VibeCheck!');
	});

	context.subscriptions.push(disposable);

	// --- Task 1: fake "hardcoded password" diagnostic ---
	const diagnostics = vscode.languages.createDiagnosticCollection('vibecheck');
	context.subscriptions.push(diagnostics);

	const check = (doc: vscode.TextDocument) => {
		if (!doc.fileName.endsWith('test.py')) { return; }
		const found: vscode.Diagnostic[] = [];
		for (let i = 0; i < doc.lineCount; i++) {
			const line = doc.lineAt(i);
			if (line.text.includes('password')) {
				const d = new vscode.Diagnostic(
					line.range,
					'Hardcoded password detected.',
					vscode.DiagnosticSeverity.Error
				);
				d.source = 'VibeCheck';
				found.push(d);
			}
		}
		diagnostics.set(doc.uri, found);
	};

	// Check files already open, and any opened later
	vscode.workspace.textDocuments.forEach(check);
	context.subscriptions.push(vscode.workspace.onDidOpenTextDocument(check));
}


export function deactivate() {}
