// Imports 'vscode' module that contains VS Code extension API and reference it with the alias vscode in your code below
import * as vscode from 'vscode';

// Importing spawn from node:child_process to run external commands for scanning codebase
import { spawn } from 'node:child_process';
import * as os from 'node:os';
import * as path from 'node:path';
import { loadReports, type ScanSummary } from './reports';
import {rmSync} from 'node:fs';

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

	private view?: vscode.WebviewView;
	private latestSummary?: ScanSummary;

	// True while a scan is running, so a second click can't start an overlapping scan.
	private scanning = false;

	// Constructor for the VibeCheckSidebar class that takes an extensionUri parameter and assigns it to a private member variable
	constructor(private readonly extensionUri: vscode.Uri) {}
	
	// Method that sets up the webview when the sidebar is opened, including HTML content and message listeners for scan and edit commands.
	public resolveWebviewView(webviewView: vscode.WebviewView, context: vscode.WebviewViewResolveContext, token: vscode.CancellationToken) {
		this.view = webviewView;

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
			//  If the webview is ready and previous scan results exists, send them to the webview to display.
			if (message.command === 'ready' && this.latestSummary) {
				webviewView.webview.postMessage({
					type: 'scanResults',
					summary: this.latestSummary
				});
			}
		});

		webviewView.onDidDispose(() => {listener.dispose();});

		// Wordmark logo for webview
		const logoUri = webviewView.webview.asWebviewUri(
			vscode.Uri.joinPath(
				this.extensionUri,
				'media',
				'vibecheck-wordmark.svg'
			)
		);
		
		// HTML content for the webview.
		webviewView.webview.html = `
			<!DOCTYPE html>
			<html lang="en">
				<head>
					<meta charset="UTF-8">
					<meta name="viewport" content="width=device-width, initial-scale=1.0">
					<title>VibeCheck</title>

					<!-- Adding CSS styles for the webview -->
					<style>
						body {
							padding: 16px;
							font-family: var(--vscode-font-family);
							font-size: var(--vscode-font-size);
							color: var(--vscode-foreground);
							background: var(--vscode-sideBar-background);
						}
						p {
							line-height: 1.5;
						}
						/* Styling for the action buttons in the webview */
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
							background: #32B985;
							color: #10251C;
						}
						.actions button:hover {
                			background: #40C995;
          	  			}
            			.actions button:focus-visible {
                			outline: 2px solid var(--vscode-focusBorder);
                			outline-offset: 2px;
            			}
            			.actions button[hidden] {
                			display: none;
            			}
						/* Styling for the findings list and its elements */
						.findings-header {
							display: flex;
							justify-content: space-between;
							padding: 0 10px;
							margin-bottom: 10px;
							font-size: 12px;
							color: var(--vscode-descriptionForeground);
						}
						#findings-list {
							padding: 0;
							margin: 0;
						}
						#findings-list li {
							list-style: none;
							position: relative;
							isolation: isolate;
							box-sizing: border-box;
							min-height: 44px;
							padding: 12px 10px;
							margin: 0 0 8px;
						}
						.finding-label {
							display: flex;
							align-items: center;
							justify-content: space-between;
							gap: 14px;
							font-size: 14px;
							line-height: 1.45;
						}
						.finding-name {
							min-width: 0;
							overflow-wrap: anywhere;
						}
						.finding-count {
							flex-shrink: 0;
							font-weight: 600;
							font-variant-numeric: tabular-nums;
						}
						.finding-bar {
							position: absolute;
							top: 0;
							bottom: 0;
							left: 0;
							z-index: -1;
							border-radius: 3px;
							background: #D97879;
							opacity: 0.17;
						}
						#findings-total {
							display: flex;
							align-items: baseline;
							flex-wrap: wrap;
							gap: 8px;
							margin: 16px 0 20px;
						}
						.findings-number {
							font-size: 25px;
							font-weight: 600;
							line-height: 1;
							font-variant-numeric: tabular-nums;
						}
						#scan-results {
							margin-top: 50px;
						}
						/* Styling for the summary horizontal bar chart and its elements */
						.distribution-caption {
							font-size: 12px;
							color: var(--vscode-descriptionForeground);
							margin: 0 0 6px;
						}
						/* Hides the findings strip and header when there are no findings to display */
						#findings-strip[hidden] {
							display: none;
						}
						.findings-header[hidden] {
							display: none;
						}
						#findings-strip {
							display: flex;
							height: 14px;
							border-radius: 4px;
							overflow: hidden;
							margin-bottom: 20px;
						}
						.finding-swatch {
							width: 8px;
							height: 8px;
							border-radius: 2px;
							flex-shrink: 0;
						}
						.finding-name {
							flex: 1;
							min-width: 0;
							overflow-wrap: anywhere;
						}
					</style>
				</head>

				<body>
					<img 
						src="${logoUri}" 
						alt="VibeCheck" 
						style="width: 240px; max-width: 100%; height: auto;"
					>
					<p>Scan AI-generated code across your codebase for potential security vulnerabilities and exposed secrets, then review proposed edits to address the findings.</p>
					<p>Click <b>Run scan</b> to get started.</p>
					
					<div class="actions">
            			<button id="scan-button">Run scan</button>
            			<button id="edit-button">View proposed edits</button>
        			</div>

					<!-- Section to display summarized horizontal bar chart and findings with their counts. Hidden by default until scan results are available. -->
					<section id="scan-results" hidden>
						<h2>Scan results</h2>
						<p id = "findings-total"></p>
						<p class = "distribution-caption">Total findings</p>
						<div id = "findings-strip" aria-label = "Findings by issue type"></div>
						<div class = "findings-header">
							<span>Issue type</span>
							<span>Count</span>
						</div>
						<ul id="findings-list"></ul>
					</section>

					<!-- Adding listener for button clicks to trigger scan and edit commands in the extension -->
					<script>
						const vscode = acquireVsCodeApi();
						const scanButton = document.getElementById('scan-button');
						const editButton = document.getElementById('edit-button');

						// Predefined colors for different issue types in the findings summary.
						const issueColors = ['#809FE3', '#D97879', '#B19ADD', '#D8AC67', '#78B7C5', '#CF91B3', '#A3D9A5', '#E0B0FF', '#FFB347', '#FF6961', '#77DD77', '#CBAACB', '#FDFD96', '#AEC6CF', '#FFDAB9'];

						// Map to store the assigned color for each unique issue type based on its scanner and name.
						const colorByIssue = new Map();

						function getIssueColor(category) {
							const key = category.scanner + ':' + category.name;

							if (!colorByIssue.has(key)) {
								const color = issueColors[colorByIssue.size % issueColors.length];
								colorByIssue.set(key, color);
							}

							return colorByIssue.get(key);
						}

						// Adding event listeners for the scan and edit buttons to send messages to the extension when clicked.
						scanButton.addEventListener('click', () => {
							vscode.postMessage({ command: 'scan' });
						});

						editButton.addEventListener('click', () => {
							vscode.postMessage({ command: 'edit' });
						});

						// Adding a message listener to receive scan results from the extension and update the webview with the findings summary.
						window.addEventListener('message', event => {
							const message = event.data;

							// Ignoring messages that are not scan results and exiting the listener early.
							if (message.type !== 'scanResults') {
								return;
							}

							const results = document.getElementById('scan-results');
							const total = document.getElementById('findings-total');
							const list = document.getElementById('findings-list');

							// Show the scan results section and clear any previous findings.
							results.hidden = false;
							list.replaceChildren();

							// Hides the findings strip and header when there are no findings to display. Replaces the findings strip with a new one to ensure it is empty before adding new segments.
							const strip = document.getElementById('findings-strip');
							strip.replaceChildren();

							// Evaluates whether findings exist. Strip remains hidden if there are no findings, and the findings header is also hidden. If findings exist, the findings strip and header are shown.
							const hasFindings = message.summary.totalFindings > 0;
							strip.hidden = !hasFindings;

							document.querySelector('.distribution-caption').hidden = !hasFindings;
							document.querySelector('.findings-header').hidden = !hasFindings;

							const findingCount = message.summary.totalFindings;

							const number = document.createElement('span');
							number.className = 'findings-number';
							number.textContent = String(findingCount);

							const caption = document.createElement('span');
							caption.textContent = findingCount === 1
								? 'finding detected'
								: 'findings detected';

							total.replaceChildren(number, caption);

							// Loop through each category of findings and create a list item with a colored bar, label, and count for each finding type.
							for (const category of message.summary.categories) {
								// Create a list item for each finding category, colored bar representing the share of findings.
								const item = document.createElement('li');
								const color = getIssueColor(category);
								const percentage = category.count / message.summary.totalFindings * 100;

								// Create a segment for the findings strip that represents the share of findings for this category.
								const segment = document.createElement('div');
								segment.style.width = percentage + '%';
								segment.style.background = color;
								segment.setAttribute('aria-label', category.name + ': ' + category.count + ' findings');
								strip.appendChild(segment);

								// For small colored square in findings list.
								const swatch = document.createElement('span');
								swatch.className = 'finding-swatch';
								swatch.style.background = color;
								swatch.setAttribute('aria-hidden', 'true');

								// Adding label, name, and count for each finding category in the findings list. Capitalizing first character for readability.
								const label = document.createElement('div');
								label.className = 'finding-label';
								const readableName = category.name.replace(/-/g, ' ');
								const displayName = readableName.charAt(0).toUpperCase() + readableName.slice(1);
								const name = document.createElement('span');
								name.className = 'finding-name';
								name.textContent = displayName;
								
								// Adding count for each finding category in the findings list.
								const count = document.createElement('span');
								count.className = 'finding-count';
								count.textContent = String(category.count);
								count.setAttribute('aria-label', category.count + ' findings');

								label.append(swatch, name, count);

								const bar = document.createElement('div');
								bar.className = 'finding-bar';
								bar.style.width = percentage + '%';
								bar.style.background = color;
								bar.setAttribute('aria-hidden', 'true');

								item.append(bar, label);
								list.appendChild(item);
							}
						});

						// Tell the extension the webview is ready so it can resend saved results.
						vscode.postMessage({ command: 'ready' });
					</script>
				</body>
    		</html>
		`;
	}

	// Creating Scan function to connect with opengrep and trufflehog runner.py files to scan the codebase for vulnerabilities.
	public scan() {
		// Preliminary check to ensure that a workspace folder is open.
		const folders = vscode.workspace.workspaceFolders;
		if (!folders || folders.length === 0) {
			vscode.window.showErrorMessage('No workspace folder is open. Please open a folder and try again.');
			return;
		}

		// To prevent second scan from starting while one is already running.
		if (this.scanning) {
			vscode.window.showWarningMessage('A scan is already running.');
			return;
		}
		this.scanning = true;

		// Displaying notification message in VS Code/Debug Console to indicate that a scan has been requested.
		vscode.window.showInformationMessage('Scan requested.');
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

		const outputPath = targetPath;

		// Clearing older reports before starting scan runners.
		try {
			for (const name of ['findings.json', 'trufflehog_report.json']) {
				rmSync(path.join(outputPath, name), { force: true });
			}
		} catch (error) {
			const message = error instanceof Error
				? error.message
				: String(error);

			vscode.window.showErrorMessage(`Could not clear old reports: ${message}`);

			this.scanning = false;
			return;
		}

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

		let runnersCompleted = 0;
		let scanFailed = false;

		// Display a VS Code notification if runners cannot start.
		opengrepScanner.on('error', error => {
			scanFailed = true;
			vscode.window.showErrorMessage(`Could not start Opengrep runner: ${error.message}`);
		});
		trufflehogScanner.on('error', error => {
			scanFailed = true;
			vscode.window.showErrorMessage(`Could not start Trufflehog runner: ${error.message}`);
		});

		const markRunnerCompleted = async () => {
			runnersCompleted++;

			// Wait until both runners have completed.
			if (runnersCompleted !== 2) {
				return;
			}

			try {
				// Both scanners must succeed before loading their reports.
				if (scanFailed) {
					vscode.window.showErrorMessage('Scan failed. Both Opengrep and TruffleHog must complete successfully.');
					return;
				}

				const summary = await loadReports(outputPath);

				// Saves the scan results so they can be shown again later.
				this.latestSummary = summary;

				// Send the results to the sidebar.
				this.view?.webview.postMessage({
					type: 'scanResults',
					summary
				});

				console.log('Combined scan results:', JSON.stringify(summary, null, 2));
			
			} catch (error) {
				const message = error instanceof Error
					? error.message
					: String(error);

				vscode.window.showErrorMessage(
					`Could not load scan results: ${message}`
				);
			} finally {
				this.scanning = false;
			}
		};

		// Closing the Opengrep scanner process and displaying appropriate messages in VS Code.
		opengrepScanner.once('close', (code, signal) => {
			if (code === 0) {
				console.log('Opengrep runner completed. View report at:', path.join(outputPath, 'findings.json'));
			} 
			else {
				scanFailed = true;
				console.error('Opengrep runner failed:', signal ? 'signal ' + signal : 'exit code ' + code);
			}
			void markRunnerCompleted();
		});

		// Closing the Trufflehog scanner process and displaying appropriate messages in VS Code.
		trufflehogScanner.once('close', (code, signal) => {
			if (code === 0 || code === 1) {
				console.log('Trufflehog runner completed. View report at:', path.join(outputPath, 'trufflehog_report.json'));
			} 
			else {
				scanFailed = true;
				console.error('Trufflehog runner failed:', signal ? 'signal ' + signal : 'exit code ' + code);
			}
			void markRunnerCompleted();
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
