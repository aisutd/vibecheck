import * as path from 'node:path';
import { lstat, mkdir, mkdtemp, realpath, writeFile } from 'node:fs/promises';

export const REPORTS_FOLDER = '.vibecheck';

export async function ensureReportsFolder(projectRoot: string): Promise<string> {
	const folder = path.join(await realpath(projectRoot), REPORTS_FOLDER);

	try {
		await mkdir(folder, { mode: 0o700 });
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== 'EEXIST') {
			throw error;
		}
	}

	const info = await lstat(folder);
	if (info.isSymbolicLink() || !info.isDirectory()) {
		throw new Error('.vibecheck must be a real directory.');
	}

	try {
		await writeFile(path.join(folder, '.gitignore'), '*\n', { flag: 'wx' });
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== 'EEXIST') {
			throw error;
		}
	}

	return mkdtemp(path.join(folder, 'scan-'));
}