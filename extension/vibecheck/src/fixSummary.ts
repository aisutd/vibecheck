// Records each accepted fix in summary.md.

import * as vscode from 'vscode';
import * as path from 'node:path';
import { execFile } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { findPython } from './python';

const SUMMARY_FILE = 'summary.md';
const DATA_FILE = 'summary-data.json';
const SECRET_PLACEHOLDER = '[hidden: this line contained a secret]';


export function isObject(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}


export async function readFindings(reportPath: string): Promise<unknown[]> {
	try {
		const report: unknown = JSON.parse(await readFile(reportPath, 'utf8'));
		return isObject(report) && Array.isArray(report.findings) ? report.findings : [];
	} catch {
		return [];
	}
}


export function firstSentence(text: string): string {
	const oneLine = text.replace(/\s+/g, ' ').trim();
	const end = oneLine.search(/[.!?](\s|$)/);
	return end === -1 ? oneLine : oneLine.slice(0, end + 1);
}

interface Issue {
	line: number;
	message: string;
	secret: boolean;
}

interface DiffStep {
	kind: 'same' | 'removed' | 'added';
	text: string;
	oldLine: number;
}

interface ChangeGroup {
	line: number;
	removed: string[];
	added: string[];
}

interface ChangeBlock {
	line: number;
	explanation: string;
	lines: string[];
}

interface FileFixes {
	file: string;
	fixedAt: string;
	fixCount: number;
	changes: ChangeBlock[];
}

async function issuesForFile(projectRoot: string, relativePath: string): Promise<Issue[]> {
	const issues: Issue[] = [];

	for (const finding of await readFindings(path.join(projectRoot, 'findings.json'))) {
		if (isObject(finding) && finding.file === relativePath) {
			issues.push({ line: Number(finding.start_line), message: String(finding.message ?? ''), secret: false });
		}
	}

	
	for (const finding of await readFindings(path.join(projectRoot, 'trufflehog_report.json'))) {
		if (isObject(finding) && finding.file === relativePath) {
			issues.push({ line: Number(finding.line), message: `Possible ${finding.detector} secret found in the code.`, secret: true });
		}
	}

	return issues;
}

// Compares old and new code line by line.

function diffSteps(oldText: string, newText: string): DiffStep[] {
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

	
	const steps: DiffStep[] = [];
	let i = 0;
	let j = 0;
	while (i < n && j < m) {
		if (a[i] === b[j]) {
			steps.push({ kind: 'same', text: a[i], oldLine: i + 1 });
			i++;
			j++;
		} else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
			steps.push({ kind: 'removed', text: a[i], oldLine: i + 1 });
			i++;
		} else {
			steps.push({ kind: 'added', text: b[j], oldLine: i + 1 });
			j++;
		}
	}
	while (i < n) {
		steps.push({ kind: 'removed', text: a[i], oldLine: i + 1 });
		i++;
	}
	while (j < m) {
		steps.push({ kind: 'added', text: b[j], oldLine: i + 1 });
		j++;
	}
	return steps;
}


function groupChanges(steps: DiffStep[]): ChangeGroup[] {
	const groups: ChangeGroup[] = [];
	let current: ChangeGroup | undefined;

	for (const step of steps) {
		if (step.kind === 'same') {
			current = undefined;
			continue;
		}
		if (!current) {
			current = { line: step.oldLine, removed: [], added: [] };
			groups.push(current);
		}
		(step.kind === 'removed' ? current.removed : current.added).push(step.text);
	}

	
	return groups.filter(g => [...g.removed, ...g.added].some(line => line.trim()));
}


function relatedIssues(group: ChangeGroup, issues: Issue[]): Issue[] {
	const lastLine = group.line + Math.max(group.removed.length, 1) - 1;
	return issues.filter(issue => issue.line >= group.line && issue.line <= lastLine);
}


function hideSecrets(group: ChangeGroup, issues: Issue[]): ChangeGroup {
	if (!relatedIssues(group, issues).some(issue => issue.secret)) {
		return group;
	}
	return { ...group, removed: group.removed.map(() => SECRET_PLACEHOLDER) };
}


function fallbackExplanation(group: ChangeGroup, issues: Issue[]): string {
	const related = relatedIssues(group, issues);
	if (related.length > 0) {
		const messages = [...new Set(related.map(issue => firstSentence(issue.message)))];
		return 'Fixes: ' + messages.join(' ');
	}

	const importLine = /^\s*(import\b|from\s+\S+\s+import\b|(const|let|var)\s+.+=\s*require\()/;
	if (group.removed.length === 0 && group.added.every(line => !line.trim() || importLine.test(line))) {
		return 'Adds an import the fix needs.';
	}

	return 'Supporting change for the fix.';
}

// Asks Gemini though python. 
function explainWithGemini(extensionPath: string, groups: ChangeGroup[], issues: Issue[]): Promise<string[] | undefined> {
	if (groups.length === 0) {
		return Promise.resolve([]);
	}

	const repoRoot = path.resolve(extensionPath, '..', '..');
	const script = path.join(repoRoot, 'dataset', 'gemini', 'fix_and_diff.py');
	const input = JSON.stringify({
		changes: groups.map(group => ({
			line: group.line,
			removed: group.removed,
			added: group.added,
			finding: relatedIssues(group, issues).map(issue => firstSentence(issue.message)).join(' ')
		}))
	});

	return new Promise(resolve => {
		const child = execFile(
			findPython(repoRoot),
			[script, '--explain'],
			{ cwd: repoRoot, timeout: 60_000, maxBuffer: 1024 * 1024 },
			(error, stdout, stderr) => {
				if (error) {
					console.warn('Vibe Check: Gemini explanations unavailable:', stderr || error.message);
					resolve(undefined);
					return;
				}
				try {
					const parsed: unknown = JSON.parse(stdout);
					const explanations = isObject(parsed) ? parsed.explanations : undefined;
					const valid = Array.isArray(explanations)
						&& explanations.length === groups.length
						&& explanations.every(item => typeof item === 'string');
					resolve(valid ? (explanations as string[]) : undefined);
				} catch {
					resolve(undefined);
				}
			}
		);
		child.stdin?.end(input);
	});
}


function dedent(lines: string[]): string[] {
	const indents = lines.filter(line => line.trim()).map(line => line.length - line.trimStart().length);
	const shared = indents.length > 0 ? Math.min(...indents) : 0;
	return lines.map(line => line.slice(shared));
}


function toChangeBlock(group: ChangeGroup, explanation: string): ChangeBlock {
	const body = dedent([...group.removed, ...group.added]);
	const removed = body.slice(0, group.removed.length).map(line => '- ' + line);
	const added = body.slice(group.removed.length).map(line => '+ ' + line);
	return { line: group.line, explanation, lines: [...removed, ...added] };
}


async function loadRecords(dataPath: string): Promise<FileFixes[]> {
	try {
		const parsed: unknown = JSON.parse(await readFile(dataPath, 'utf8'));
		return Array.isArray(parsed) ? (parsed as FileFixes[]) : [];
	} catch {
		return [];
	}
}


function renderSummary(records: FileFixes[]): string {
	const lines = ['# Vibe Check Fix Summary', ''];

	records.forEach((record, index) => {
		if (index > 0) {
			lines.push('---', '');
		}

		lines.push(`## ${record.file}`);
		lines.push(record.fixCount > 1
			? `Fixed ${record.fixCount} times, most recently on ${record.fixedAt}`
			: `Fixed on ${record.fixedAt}`);
		lines.push('');

		if (record.changes.length === 0) {
			lines.push('No lines changed.', '');
		}

		for (const change of record.changes) {
			lines.push(`**Line ${change.line}:** ${change.explanation}`);
			lines.push('````diff', ...change.lines, '````', '');
		}
	});

	return lines.join('\n');
}


export async function appendFixSummary(
	context: vscode.ExtensionContext,
	fileUri: vscode.Uri,
	oldText: string,
	newText: string
): Promise<void> {
	const projectRoot = (vscode.workspace.getWorkspaceFolder(fileUri) ?? vscode.workspace.workspaceFolders?.[0])?.uri.fsPath;
	const relativePath = projectRoot ? path.relative(projectRoot, fileUri.fsPath) : path.basename(fileUri.fsPath);

	const issues = projectRoot ? await issuesForFile(projectRoot, relativePath) : [];
	const groups = groupChanges(diffSteps(oldText, newText)).map(group => hideSecrets(group, issues));

	// Ask Gemini to explain each change; fall back to the scan findings if it can't.
	const status = vscode.window.setStatusBarMessage('$(sync~spin) Vibe Check: writing fix summary...');
	const explanations = await explainWithGemini(context.extensionPath, groups, issues);
	status.dispose();

	const newChanges = groups.map((group, i) => toChangeBlock(group, explanations?.[i] ?? fallbackExplanation(group, issues)));
	const fixedAt = new Date().toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }).replace(', ', ' at ');

	// The extension's private storage for this project, outside the user's code.
	const storageUri = context.storageUri ?? context.globalStorageUri;
	await vscode.workspace.fs.createDirectory(storageUri);
	const dataPath = path.join(storageUri.fsPath, DATA_FILE);
	const summaryPath = path.join(storageUri.fsPath, SUMMARY_FILE);

	// Update this file's entry if it was fixed before; either way, move it to the top.
	const records = await loadRecords(dataPath);
	const index = records.findIndex(record => record.file === relativePath);

	if (index >= 0) {
		const [record] = records.splice(index, 1);
		record.changes.push(...newChanges);
		record.fixedAt = fixedAt;
		record.fixCount = (record.fixCount ?? 1) + 1;
		records.unshift(record);
	} else {
		records.unshift({ file: relativePath, fixedAt, fixCount: 1, changes: newChanges });
	}

	await writeFile(dataPath, JSON.stringify(records, null, 2), 'utf8');
	await writeFile(summaryPath, renderSummary(records), 'utf8');
	await vscode.commands.executeCommand('markdown.showPreviewToSide', vscode.Uri.file(summaryPath));
}