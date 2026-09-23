# VibeCheck

## Description

VibeCheck is an AI security companion for detecting and repairing vulnerabilities in AI-generated applications. It combines static analysis with a specialized language model inside a VS Code extension to find logic flaws and hardcoded secrets and propose safer patches.

## Planned Technologies

- Python and JavaScript/TypeScript
- VS Code Extension API
- Hugging Face Transformers, TRL, PyTorch, and Ollama
- Opengrep, TruffleHog, Tree-sitter, and SQLite

## Docker Setup

Make sure Docker Desktop is installed and running.

```bash
docker compose up -d
docker compose down
docker compose ps
```

This is a generic starter configuration. The team can add project-specific dependencies and startup commands later.
