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

	// NEW VibeCheck: Show Status command. 
	const showStatus = vscode.commands.registerCommand('vibecheck.showStatus', () => {
		// Displays a message when Show Status command runs.
		vscode.window.showInformationMessage('VibeCheck is running.');
	});

	context.subscriptions.push(showStatus);

	// Creating button to show VibeCheck status
	const button = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);

	// Setting up the status bar button for VibeCheck and creating tooltip for hovering over the button
	button.text = 'VibeCheck';
	button.tooltip = 'Show VibeCheck status';
	button.command = 'vibecheck.showStatus';
	button.show();

	context.subscriptions.push(button);
}

// This method is called when your extension is deactivated
export function deactivate() {}
