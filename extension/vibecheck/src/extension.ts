// Imports 'vscode' module that contains VS Code extension API and reference it with the alias vscode in your code below
import * as vscode from 'vscode';
import * as path from "path";
import { execFile } from "child_process";
import { registerFixDiff, showFix } from "./fixDiff";

// VS Code calls this method when the VibeCheck extension is activated
export function activate(context: vscode.ExtensionContext) {
	// Outputs to console when extension is activated
	console.log('VibeCheck extension is now active.');

	const provider = new VibeCheckSidebar();

	context.subscriptions.push(
		vscode.window.registerWebviewViewProvider(VibeCheckSidebar.viewType, provider)
	);

	// Method for scanning codebase using opengrep and trufflehog
	context.subscriptions.push(
		vscode.commands.registerCommand('vibecheck.scan', () => provider.scan())
	);

	// For editing generated code using results from fine-tuned model
	context.subscriptions.push(
		vscode.commands.registerCommand('vibecheck.edit', () => provider.edit())
	);
	// Registering the fix diff provider
	registerFixDiff(context);
	context.subscriptions.push(
		vscode.commands.registerCommand('vibecheck.fixCurrentFile', async () => {
			const editor = vscode.window.activeTextEditor;
			if (!editor) {
				vscode.window.showWarningMessage('Open a file first.');
				return;
			}

			const doc = editor.document;
			if (doc.isDirty) {
				vscode.window.showWarningMessage('Save the file first, then run Vibe Check.');
				return;
			}

			// extension lives at <repo>/extension/vibecheck
			const repoRoot = path.resolve(context.extensionPath, '..', '..');
			const python = path.join(repoRoot, '.venv', 'bin', 'python');
			const script = path.join(repoRoot, 'dataset', 'gemini', 'fix_and_diff.py');

			await vscode.window.withProgress(
				{ location: vscode.ProgressLocation.Notification, title: 'Vibe Check: asking Gemini for a fix...' },
				() =>
					new Promise<void>((resolve) => {
						execFile(
							python,
							[script, doc.uri.fsPath, '--stdout'],
							{ cwd: repoRoot, timeout: 180_000, maxBuffer: 10 * 1024 * 1024 },
							async (error, stdout, stderr) => {
								if (error) {
									vscode.window.showErrorMessage(`Vibe Check failed: ${stderr || error.message}`);
								} else {
									await showFix(doc.uri, stdout);
								}
								resolve();
							}
						);
					})
			);
		})
	);
}

// Webview provider for the VibeCheck extension that extends from VS Code Webview View Provider
class VibeCheckSidebar implements vscode.WebviewViewProvider {
	
	public static readonly viewType = 'vibecheck.sidebar';
	
	public resolveWebviewView(
		webviewView: vscode.WebviewView,
		context: vscode.WebviewViewResolveContext,
		token: vscode.CancellationToken
	) 
	{
		// Enabling scripts in the webview to allow for interactivity with buttons in HTML.
		webviewView.webview.options = {
			enableScripts: true,
		};

		// Creating a message listener to handle messages sent from the webview to the extension.
		const listener = webviewView.webview.onDidReceiveMessage((message) => {
			if (message.command === 'scan') {
				this.scan();
			}
		});

		webviewView.onDidDispose(() => {listener.dispose();});
		
		// HTML content for the webview, including a title, description, and buttons for scanning and editing.
		webviewView.webview.html = `
			<!DOCTYPE html>
			<html lang="en">

			<!-- HTML Header -->
			<head>
				<meta charset="UTF-8">
				<title>VibeCheck</title>
    		</head>

			<!-- HTML Body -->
			<body>
       			<h1>VibeCheck</h1>
        		<p>VibeCheck is a security companion tool that detects security issues in AI-generated code and proposes a fix for them.</p>
				<p>Start scanning now to find vulnerabilities.</p>
				<button id="scan-button">Run scan</button>
				<button id="edit-button">View proposed edits</button>

				<!-- Adding listener for button clicks to trigger scan and edit commands in the extension -->
				<script>
					const scanButton = document.getElementById('scan-button');
					const editButton = document.getElementById('edit-button');

					scanButton.addEventListener('click', () => {
						scanButton.textContent = 'Scan requested.';
					});

					editButton.addEventListener('click', () => {
						editButton.textContent = 'Loading proposed edits.';
					});
				</script>
    		</body>

    		</html>
`;
	}

	// Creating Scan function
	public scan() {
		// Insert trufflehog and opengrep scan logic here.
		vscode.window.showInformationMessage(
        	'Scan requested.'
    	);
	}

	// Creating Edit function
	public edit() {
		// Insert logic for editing scan results from model.
		vscode.window.showInformationMessage(
			'Loading proposed edits.'
		)
	}
}


// Method called when VibeCheck extension is deactivated.
export function deactivate() {}
