import * as vscode from "vscode";

const SCHEME = "vibecheck-fixed";

// The fixed code for each diff, keyed by the fixed document's URI
const fixes = new Map<string, string>();

class FixedContentProvider implements vscode.TextDocumentContentProvider {
  private emitter = new vscode.EventEmitter<vscode.Uri>();
  readonly onDidChange = this.emitter.event;

  provideTextDocumentContent(uri: vscode.Uri): string {
    return fixes.get(uri.toString()) ?? "";
  }

  refresh(uri: vscode.Uri): void {
    this.emitter.fire(uri);
  }
}

let provider: FixedContentProvider;

export function registerFixDiff(context: vscode.ExtensionContext): void {
  provider = new FixedContentProvider();
  context.subscriptions.push(
    vscode.workspace.registerTextDocumentContentProvider(SCHEME, provider)
  );
}

export async function showFix(originalUri: vscode.Uri, fixedCode: string): Promise<void> {
  const doc = await vscode.workspace.openTextDocument(originalUri);

  // Match the user's line endings so the diff doesn't flag every line
  const normalized = fixedCode.replace(/\r\n/g, "\n");
  const matched = doc.eol === vscode.EndOfLine.CRLF ? normalized.replace(/\n/g, "\r\n") : normalized;

  const fixedUri = originalUri.with({ scheme: SCHEME, query: Date.now().toString() });
  fixes.set(fixedUri.toString(), matched);
  provider.refresh(fixedUri);

  const name = originalUri.path.split("/").pop();
  await vscode.commands.executeCommand("vscode.diff", originalUri, fixedUri, `${name}: Vibe Check fix`);
}