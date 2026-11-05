// Used to summarize the findings from both Opengrep and TruffleHog reports into a single data structure for the webview.

import { readFile } from 'node:fs/promises';
import * as path from 'node:path';

// What single line output from each scanner should be used to categorize findings.
export interface FindingCategory {name: string; scanner: 'Opengrep' | 'TruffleHog'; count: number;}

// Number of findings in a single file, with the path relative to the scanned folder.
export interface FileSummary {path: string; count: number;}

// Summarized findings including total number of findings, categories, and files.
export interface ScanSummary {totalFindings: number; categories: FindingCategory[]; files: FileSummary[];}

// Checking to see if a value is an object (not null and not an array).
function isObject(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// Main function to load and summarize the findings from both Opengrep and TruffleHog reports.
export async function loadReports(folderPath: string): Promise<ScanSummary> {
	
    // Reading both reports.
	const [opengrepText, trufflehogText] = await Promise.all([
		readFile(path.join(folderPath, 'findings.json'), 'utf8'),
		readFile(path.join(folderPath, 'trufflehog_report.json'), 'utf8')
	]);

    // Parsing both reports from JSON strings into JavaScript objects.
	const opengrep: unknown = JSON.parse(opengrepText);
	const trufflehog: unknown = JSON.parse(trufflehogText);


    // Throwing error if parsed reports do not contain objects or if findings are in array format.
	if (!isObject(opengrep) || !Array.isArray(opengrep.findings)) {
		throw new Error('Opengrep report is missing its findings list.');
	}

	if (!isObject(trufflehog) || !isObject(trufflehog.summary)) {
		throw new Error('TruffleHog report is missing its summary.');
	}

	const summary = trufflehog.summary;

    // Throwing error if the TruffleHog scan is incomplete or if detector counts are missing or invalid.
	if (summary.scan_complete !== true) {
		throw new Error('TruffleHog scan is incomplete.');
	}

    // Throwing error if the TruffleHog report is missing detector counts.
	if (!isObject(summary.by_detector)) {
		throw new Error('TruffleHog report is missing its detector counts.');
	}

	// Counting each Opengrep rule.
	const ruleCounts = new Map<string, number>();

    // Going through each finding in the Opengrep report and counting the occurrences of each rule ID.
	for (const finding of opengrep.findings) {
		if (!isObject(finding) || typeof finding.rule_id !== 'string' || !finding.rule_id.trim()) {
			throw new Error('An Opengrep finding has an invalid rule ID.');
		}

		const ruleId = finding.rule_id;
		ruleCounts.set(ruleId, (ruleCounts.get(ruleId) ?? 0) + 1);
	}

    // Declaring an array to hold the categorized findings from both scanners.
	const categories: FindingCategory[] = [];

    // Adding the counted Opengrep rules to the categories array.
	for (const [name, count] of ruleCounts) {
		categories.push({ name, scanner: 'Opengrep', count });
	}

	// Reuse TruffleHog's existing counts.
	let secretCount = 0;

	for (const [name, count] of Object.entries(summary.by_detector)) {
		if (!name.trim() || typeof count !== 'number' || !Number.isSafeInteger(count) || count < 0) {
			throw new Error('TruffleHog report contains an invalid detector count.');
		}

		secretCount += count;

		if (count > 0) {
			categories.push({ name, scanner: 'TruffleHog', count });
		}
	}

	if (secretCount !== summary.total_findings) {
		throw new Error('TruffleHog detector counts do not match its total.');
	}

	// Counting findings in each file across both scanners.
	if (!Array.isArray(trufflehog.findings)) {
		throw new Error('TruffleHog report is missing its findings list.');
	}

	const fileCounts = new Map<string, number>();

	const countFile = (file: unknown) => {
		if (typeof file !== 'string' || !file.trim()) {
			throw new Error('A finding is missing its file path.');
		}

		// Keeps paths relative to the scanned folder so the same file matches across both reports.
		const relativePath = path.isAbsolute(file) ? path.relative(folderPath, file) : file;
		fileCounts.set(relativePath, (fileCounts.get(relativePath) ?? 0) + 1);
	};

	for (const finding of opengrep.findings) {
		if (isObject(finding)) {
			countFile(finding.file);
		}
	}

	for (const finding of trufflehog.findings) {
		if (isObject(finding)) {
			countFile(finding.file);
		}
	}

	// Show the files with the most findings first.
	const files: FileSummary[] = [...fileCounts]
		.map(([filePath, count]) => ({ path: filePath, count }))
		.sort((a, b) => b.count - a.count || a.path.localeCompare(b.path));

	// Show the most frequent finding types first.
	categories.sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));

	return {
		totalFindings: opengrep.findings.length + secretCount,
		categories,
		files
	};
}