import * as vscode from "vscode";
import { appendFixSummary } from "./fixSummary";
const SCHEME = "vibecheck-fixed";

interface PendingFix {
  originalUri: vscode.Uri;   // which file we are fixing
  originalText: string;      // how the og file looked like
  fixedCode: string;         // the fixed version that is accpeted.
}

// Fixes waiting for the user to accept or reject.
const fixes = new Map<string, PendingFix>();

class FixedContentProvider implements vscode.TextDocumentContentProvider {
  private emitter = new vscode.EventEmitter<vscode.Uri>();
  readonly onDidChange = this.emitter.event;

  provideTextDocumentContent(uri: vscode.Uri): string {
    return fixes.get(uri.toString())?.fixedCode ?? "";
  }

  refresh(uri: vscode.Uri): void {
    this.emitter.fire(uri);
  }
}

let provider: FixedContentProvider;
let extensionContext: vscode.ExtensionContext;

export function registerFixDiff(context: vscode.ExtensionContext): void {
  extensionContext = context;
  provider = new FixedContentProvider();
  context.subscriptions.push(
    vscode.workspace.registerTextDocumentContentProvider(SCHEME, provider),
    vscode.commands.registerCommand("vibecheck.acceptFix", acceptFix),
    vscode.commands.registerCommand("vibecheck.rejectFix", rejectFix),
    vscode.window.tabGroups.onDidChangeTabs(updateButtons),
    vscode.window.tabGroups.onDidChangeTabGroups(updateButtons)
  );
}

export async function showFix(originalUri: vscode.Uri, fixedCode: string): Promise<void> {
  const doc = await vscode.workspace.openTextDocument(originalUri);

  // Match the user's line endings so the diff doesn't flag every line
  const normalized = fixedCode.replace(/\r\n/g, "\n");
  const matched = doc.eol === vscode.EndOfLine.CRLF ? normalized.replace(/\n/g, "\r\n") : normalized;

  const fixedUri = originalUri.with({ scheme: SCHEME, query: Date.now().toString() });

  fixes.set(fixedUri.toString(), {
    originalUri,
    originalText: doc.getText(),
    fixedCode: matched,
  });

  provider.refresh(fixedUri);

  const name = originalUri.path.split("/").pop();
  await vscode.commands.executeCommand("vscode.diff", originalUri, fixedUri, `${name}: Vibe Check fix`);
  updateButtons();
}

function activeFixKey(): string | undefined {
  const input = vscode.window.tabGroups.activeTabGroup.activeTab?.input;
  if (input instanceof vscode.TabInputTextDiff && fixes.has(input.modified.toString())) {
    return input.modified.toString();
  }
  return undefined;
}

function updateButtons(): void {
  vscode.commands.executeCommand("setContext", "vibecheck.fixDiffActive", activeFixKey() !== undefined);
}

async function acceptFix(): Promise<void> {
  const key = activeFixKey();
  const fix = key ? fixes.get(key) : undefined;
  if (!key || !fix) {
    vscode.window.showWarningMessage("No Vibe Check fix to apply here.");
    return;
  }

  const doc = await vscode.workspace.openTextDocument(fix.originalUri);

  if (doc.getText() !== fix.originalText) {
    vscode.window.showWarningMessage("This file changed since the fix was made. Run Vibe Check again.");
    return;
  }

  const edit = new vscode.WorkspaceEdit();
  const fullRange = new vscode.Range(doc.positionAt(0), doc.positionAt(doc.getText().length));
  edit.replace(fix.originalUri, fullRange, fix.fixedCode);
  await vscode.workspace.applyEdit(edit);

  fixes.delete(key);
  await vscode.commands.executeCommand("workbench.action.closeActiveEditor");
  await vscode.window.showTextDocument(doc);
  vscode.window.showInformationMessage("Vibe Check fix applied. Undo with Cmd/Ctrl+Z, or save to keep it.");
  try {
    await appendFixSummary(extensionContext, fix.originalUri, fix.originalText, fix.fixedCode);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    vscode.window.showWarningMessage(`Fix applied, but the summary couldn't be updated: ${message}`);
  }
}

async function rejectFix(): Promise<void> {
  const key = activeFixKey();
  if (key) {
    fixes.delete(key);
  }
  await vscode.commands.executeCommand("workbench.action.closeActiveEditor");
  vscode.window.showInformationMessage("Vibe Check fix rejected. Your file was not changed.");
}