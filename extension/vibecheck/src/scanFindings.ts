// Writes scan-findings.md.

import * as vscode from 'vscode';
import * as path from 'node:path';
import { writeFile } from 'node:fs/promises';
import { isObject, readFindings, firstSentence } from './fixSummary';

const FINDINGS_FILE = 'scan-findings.md';



interface FindingLine {
	line: number;
	text: string;
}


export async function writeScanFindings(reportFolder: string): Promise<void> {
	const byFile = new Map<string, FindingLine[]>();

	const add = (file: unknown, line: unknown, text: string) => {
		if (typeof file !== 'string' || !file.trim()) {
			return;
		}
		const relativePath = file;
		const lineNumber = Number(line);
		const list = byFile.get(relativePath) ?? [];
		list.push({ line: Number.isFinite(lineNumber) ? lineNumber : 0, text });
		byFile.set(relativePath, list);
	};

	for (const finding of await readFindings(path.join(reportFolder, 'findings.json'))) {
		if (isObject(finding)) {
			add(finding.file, finding.start_line, firstSentence(String(finding.message ?? '')));
		}
	}

	
	for (const finding of await readFindings(path.join(reportFolder, 'trufflehog_report.json'))) {
		if (isObject(finding)) {
			add(finding.file, finding.line, `Possible ${finding.detector} secret found in the code.`);
		}
	}


	const files = [...byFile].sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));
	const total = files.reduce((sum, [, list]) => sum + list.length, 0);
	const scannedAt = new Date().toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }).replace(', ', ' at ');

	const lines = ['# Vibe Check Findings', ''];

	if (total === 0) {
		lines.push(`Scanned on ${scannedAt}`, '', 'No issues found in this project.', '');
	} else {
		const findingWord = total === 1 ? 'finding' : 'findings';
		const fileWord = files.length === 1 ? 'file' : 'files';
		lines.push(`Scanned on ${scannedAt} · ${total} ${findingWord} in ${files.length} ${fileWord}`, '');

		for (const [file, list] of files) {
			lines.push(`## ${file}`);
			for (const finding of list.sort((a, b) => a.line - b.line)) {
				lines.push(finding.line > 0 ? `- Line ${finding.line}: ${finding.text}` : `- ${finding.text}`);
			}
			lines.push('');
		}
	}
	const findingsPath = path.join(reportFolder, FINDINGS_FILE);
	await writeFile(findingsPath, lines.join('\n'), { encoding: 'utf8', flag: 'wx' });
	await vscode.commands.executeCommand('markdown.showPreviewToSide', vscode.Uri.file(findingsPath));
}