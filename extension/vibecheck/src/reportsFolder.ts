// Creates the vibecheck-reports folder in the user's project.

import * as path from 'node:path';
import { mkdir, writeFile } from 'node:fs/promises';

export const REPORTS_FOLDER = 'vibecheck-reports';

// Makes sure the folder exists (with a .gitignore so it's never committed) and returns its path.
export async function ensureReportsFolder(projectRoot: string): Promise<string> {
	const folder = path.join(projectRoot, REPORTS_FOLDER);
	await mkdir(folder, { recursive: true });

	// "wx" only creates the file if it doesn't already exist, so a user's edits are kept.
	try {
		await writeFile(path.join(folder, '.gitignore'), '*\n', { flag: 'wx' });
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== 'EEXIST') {
			throw error;
		}
	}

	return folder;
}