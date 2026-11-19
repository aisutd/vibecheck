// Picks which Python to run. 

import * as path from 'node:path';
import { existsSync } from 'node:fs';

// Uses the project's .venv if it exists, otherwise the system Python for this OS.
export function findPython(repoRoot: string): string {
	const venvPython = process.platform === 'win32'
		? path.join(repoRoot, '.venv', 'Scripts', 'python.exe')
		: path.join(repoRoot, '.venv', 'bin', 'python');

	if (existsSync(venvPython)) {
		return venvPython;
	}
	return process.platform === 'win32' ? 'python' : 'python3';
}