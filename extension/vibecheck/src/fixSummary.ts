// Records each accepted fix in a summary.md .

import * as vscode from 'vscode';
import * as path from 'node:path';
import { readFile, appendFile, access } from 'node:fs/promises';

const SUMMARY_FILE = 'summary.md';
const SUMMARY_HEADER = '# Vibe Check Fix Summary\n\n';


interface Problem {
	line: string;
	issue: string;
}

// Checking to see if a value is an object (not null and not an array).
function isObject(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// Reads a scan report, returns its findings list, or an empty list if the report doesn't exist.
async function readFindings(reportPath: string): Promise<unknown[]> {
	try {
		const report: unknown = JSON.parse(await readFile(reportPath, 'utf8'));
		return isObject(report) && Array.isArray(report.findings) ? report.findings : [];
	} catch {
		return [];
	}
}

// Collects the problems for one file from both scan reports.
async function findProblems(projectRoot: string, relativePath: string): Promise<Problem[]> {
	const problems: Problem[] = [];

	for (const finding of await readFindings(path.join(projectRoot, 'findings.json'))) {
		if (isObject(finding) && finding.file === relativePath) {
			problems.push({
				line: String(finding.start_line ?? '?'),
				issue: String(finding.message ?? '')
			});
		}
	}

	for (const finding of await readFindings(path.join(projectRoot, 'trufflehog_report.json'))) {
		if (isObject(finding) && finding.file === relativePath) {
			problems.push({
				line: String(finding.line ?? '?'),
				issue: `Possible ${finding.detector} secret found in the code.`
			});
		}
	}

	return problems;
}


function firstSentence(text: string): string {
	const oneLine = text.replace(/\s+/g, ' ').trim();
	const end = oneLine.search(/[.!?](\s|$)/);
	return end === -1 ? oneLine : oneLine.slice(0, end + 1);
}

// Turns the problems into a simple bulleted list.
function problemsList(problems: Problem[]): string[] {
	if (problems.length === 0) {
		return ['No scan findings recorded for this file.'];
	}
	return problems.map(p => `- Line ${p.line}: ${firstSentence(p.issue)}`);
}


function changedLines(oldText: string, newText: string): string[] {
	const a = oldText.replace(/\r\n/g, '\n').split('\n');
	const b = newText.replace(/\r\n/g, '\n').split('\n');
	const n = a.length;
	const m = b.length;

	
	const lcs: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
	for (let i = n - 1; i >= 0; i--) {
		for (let j = m - 1; j >= 0; j--) {
			lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
		}
	}

	
	const result: string[] = [];
	let i = 0;
	let j = 0;
	while (i < n && j < m) {
		if (a[i] === b[j]) {
			i++;
			j++;
		} else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
			result.push('-' + a[i++]);
		} else {
			result.push('+' + b[j++]);
		}
	}
	while (i < n) {
		result.push('-' + a[i++]);
	}
	while (j < m) {
		result.push('+' + b[j++]);
	}
	return result;
}

// Adds a section for one accepted fix to summary.md, then opens it beside the editor.
export async function appendFixSummary(
	context: vscode.ExtensionContext,
	fileUri: vscode.Uri,
	oldText: string,
	newText: string
): Promise<void> {
	const projectRoot = (vscode.workspace.getWorkspaceFolder(fileUri) ?? vscode.workspace.workspaceFolders?.[0])?.uri.fsPath;
	const relativePath = projectRoot ? path.relative(projectRoot, fileUri.fsPath) : path.basename(fileUri.fsPath);

	const problems = projectRoot ? await findProblems(projectRoot, relativePath) : [];
	const changes = changedLines(oldText, newText);

	const fixedAt = new Date().toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }).replace(', ', ' at ');

	const section = [
		`## ${relativePath}`,
		`Fixed on ${fixedAt}`,
		'',
		'### Issues found',
		...problemsList(problems),
		'',
		'### Changes made',
		'````diff',
		...changes,
		'````',
		'',
		''
	].join('\n');

	// The extension's private storage for this project, outside the user's code.
	const storageUri = context.storageUri ?? context.globalStorageUri;
	await vscode.workspace.fs.createDirectory(storageUri);
	const summaryPath = path.join(storageUri.fsPath, SUMMARY_FILE);

	// Write the title first if this is a brand-new summary; otherwise separate this fix from the last one.
	let isNewSummary = false;
	try {
		await access(summaryPath);
	} catch {
		isNewSummary = true;
	}

	await appendFile(summaryPath, isNewSummary ? SUMMARY_HEADER + section : '---\n\n' + section, 'utf8');
	await vscode.commands.executeCommand('markdown.showPreviewToSide', vscode.Uri.file(summaryPath));
}