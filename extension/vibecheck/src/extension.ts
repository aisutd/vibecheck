// Imports 'vscode' module that contains VS Code extension API and reference it with the alias vscode in your code below
import * as vscode from 'vscode';

// Importing spawn from node:child_process to run external commands for scanning codebase
import { spawn } from 'node:child_process';
import * as os from 'node:os';
import * as path from 'node:path';
import { mkdtempSync } from 'node:fs';

// VS Code calls this method when the VibeCheck extension is activated
export function activate(context: vscode.ExtensionContext) {
	// Outputs to console when extension is activated
	console.log('VibeCheck extension is now active.');

	const provider = new VibeCheckSidebar(context.extensionUri);

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
}

// Webview provider for the VibeCheck extension that extends from VS Code Webview View Provider
class VibeCheckSidebar implements vscode.WebviewViewProvider {
	
	public static readonly viewType = 'vibecheck.sidebar';

	// Constructor for the VibeCheckSidebar class that takes an extensionUri parameter and assigns it to a private member variable
	constructor(private readonly extensionUri: vscode.Uri) {}
	
	public resolveWebviewView(
		webviewView: vscode.WebviewView,
		context: vscode.WebviewViewResolveContext,
		token: vscode.CancellationToken
	) {
		// Enabling scripts in the webview to allow for interactivity with buttons in HTML.
		webviewView.webview.options = {
			enableScripts: true,
		};

		// Creating a message listener to handle messages sent from the webview to the extension.
		const listener = webviewView.webview.onDidReceiveMessage((message) => {
			if (message.command === 'scan') {
				this.scan();
			}
			if (message.command === 'edit') {
				this.edit();
			}
		});

		webviewView.onDidDispose(() => {listener.dispose();});
		
		// HTML content for the webview, including a title, description, and buttons for scanning and editing.
		webviewView.webview.html = `
			<!DOCTYPE html>
			<html lang="en">
				<head>
					<meta charset="UTF-8">
					<meta name="viewport" content="width=device-width, initial-scale=1.0">
					<title>VibeCheck</title>

					<style>
						body {
							padding: 16px;
							font-family: var(--vscode-font-family);
							font-size: var(--vscode-font-size);
							color: var(--vscode-foreground);
							background: var(--vscode-sideBar-background);
						}
						h1 {
							font-size: 22px;
							margin: 0 0 12px;
						}
						p {
							line-height: 1.5;
						}
						.actions {
							display: flex;
							flex-direction: column;
							align-items: center;
							gap: 10px;
							margin-top: 16px;
						}
						.actions button {
							box-sizing: border-box;
							width:100%;
							max-width: 320px;
							height: 25px;
							padding: 0 12px;
							border: 1px solid transparent;
							border-radius: 6px;
							font: inherit;
							cursor: pointer;
							background: var(--vscode-button-background);
							color: var(--vscode-button-foreground);
						}
						.actions button:hover {
                			background: var(--vscode-button-hoverBackground);
          	  			}
            			.actions button:focus-visible {
                			outline: 2px solid var(--vscode-focusBorder);
                			outline-offset: 2px;
            			}
            			.actions button[hidden] {
                			display: none;
            			}
					</style>
				</head>

				<body>
					<h1>VibeCheck</h1>
					<p>VibeCheck is a security companion tool that detects security issues in AI-generated code and proposes a fix for them.</p>
					<p><b>Start scanning to find vulnerabilities.</b></p>
					
					<div class="actions">
            			<button id="scan-button">Run scan</button>
            			<button id="edit-button">View proposed edits</button>
        			</div>

					<!-- Adding listener for button clicks to trigger scan and edit commands in the extension -->
					<script>
						const vscode = acquireVsCodeApi();
						const scanButton = document.getElementById('scan-button');
						const editButton = document.getElementById('edit-button');

						scanButton.addEventListener('click', () => {
							vscode.postMessage({ command: 'scan' });
						});

						editButton.addEventListener('click', () => {
							vscode.postMessage({ command: 'edit' });
						});
					</script>
				</body>
    		</html>
		`;
	}

	// Creating Scan function to connect with opengrep and trufflehog runner.py files to scan the codebase for vulnerabilities.
	public scan() {
		// Displaying notification message in VS Code to indicate that a scan has been requested.
		vscode.window.showInformationMessage(
        	'Scan requested.'
    	);

		// Preliminary check to ensure that a workspace folder is open.
		const folders = vscode.workspace.workspaceFolders;
		if (!folders || folders.length === 0) {
			vscode.window.showErrorMessage('No workspace folder is open. Please open a folder and try again.');
			return;
		}

		console.log('Preparing to scan the codebase...');

		// Starting target path at first workspace folder in selected codebase
		const targetPath = folders[0].uri.fsPath;

		// Locates the opengrep runner.py file in the opengrep directory relative to the extension's URI and constructs its file system path.
		const opengrepRunnerPath = vscode.Uri.joinPath(
			this.extensionUri,
			'..',
			'opengrep',
			'runner.py'
		).fsPath;

		// Locates the trufflehog runner.py file in the trufflehog directory relative to the extension's URI and constructs its file system path.
		const trufflehogRunnerPath = vscode.Uri.joinPath(
			this.extensionUri,
			'..',
			'trufflehog',
			'trufflehog_runner.py'
		).fsPath;

		// Logging the target path and runner path to console.
		console.log('Project to scan:', targetPath);
		console.log('Opengrep runner:', opengrepRunnerPath);
		console.log('Trufflehog runner:', trufflehogRunnerPath);

		// Outputting JSON file from runners into codebase. Possibly change this to a temporary directory in the future.
		const outputPath = targetPath;

		// Runs the Opengrep scanner script with the runner and target paths.
		console.log('Opengrep scan in progress...');
		const opengrepScanner = spawn(
			'python3',
			[opengrepRunnerPath, targetPath, '--out', outputPath],
			{
				cwd: targetPath,
				env: {
					...process.env,
					PATH: [
						path.join(os.homedir(), '.opengrep', 'cli', 'latest'),
						process.env.PATH ?? ''
					].join(path.delimiter)
				}
			}
		);

		// Runs the Trufflehog scanner script with the runner and target paths.
		console.log('Trufflehog scan in progress...');
		const trufflehogScanner = spawn(
			'python3',
			[trufflehogRunnerPath, targetPath, '--output', outputPath, '--no-verification'],
			{
				cwd: targetPath,
				env: process.env
			}
		);

		// Log the output of the runners to the debug console.
		opengrepScanner.stdout.on('data', data => {
			console.log('[Opengrep]',data.toString().trim());
		});

		trufflehogScanner.stdout.on('data', data => {
			console.log('[Trufflehog]',data.toString().trim());
		});

		// Log diagnostic output, which may include warnings or errors.
		opengrepScanner.stderr.on('data', data => {
			console.error('[Opengrep]',data.toString().trim());
		});
		trufflehogScanner.stderr.on('data', data => {
			console.error('[Trufflehog]',data.toString().trim());
		});

		// Display a VS Code notification if runners cannot start.
		opengrepScanner.on('error', error => {
			vscode.window.showErrorMessage(`Could not start Opengrep runner: ${error.message}`);
		});
		trufflehogScanner.on('error', error => {
			vscode.window.showErrorMessage(`Could not start Trufflehog runner: ${error.message}`);
		});
		
		let runnersCompleted = 0;

		const markRunnerCompleted = () => {
			runnersCompleted++;

			if (runnersCompleted === 2) {
				vscode.window.showInformationMessage(
					'Scan completed. Review reports for findings and scan errors.'
				);
			}
		};

		// Closing the Opengrep scanner process and displaying appropriate messages in VS Code.
		opengrepScanner.on('close', code => {
			if (code === 0) {
				console.log('Opengrep runner completed. View report at:', path.join(outputPath, 'findings.json'));
				markRunnerCompleted();
			} 
			else if (code !== null) {
				vscode.window.showErrorMessage(`Opengrep scanner exited with code ${code}. Check the Debug Console.`);
			}
		});

		// Closing the Trufflehog scanner process and displaying appropriate messages in VS Code.
		trufflehogScanner.on('close', code => {
			if (code === 0 || code === 1) {
				console.log('Trufflehog runner completed. View report at:', path.join(outputPath, 'trufflehog_report.json'));
				markRunnerCompleted();
			} 
			else if (code !== null) {
				vscode.window.showErrorMessage(`Trufflehog scanner exited with code ${code}. Check the Debug Console.`);
			}
		});
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
