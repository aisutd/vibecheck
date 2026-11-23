# VibeCheck

VibeCheck scans your workspace with OpenGrep and TruffleHog. It shows
findings in the VS Code sidebar and uses a local Ollama model to propose
fixes for review.

## Test setup

Start Docker Desktop and build the scanner image from the VibeCheck repo root:

```bash
docker build -f Dockerfile.scanner -t vibecheck-scanner:dev .
```

Install the test VSIX, open a project folder in VS Code, then select
**Scan** in the VibeCheck sidebar. To try **Fix**, start Ollama with the
VibeCheck model available.

The installed extension's **Fix** workflow still needs to be tested with
the VSIX.