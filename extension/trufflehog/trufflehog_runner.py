#!/usr/bin/env python3
"""Convenience entry point so the runner works straight from a checkout.

    python trufflehog_runner.py path/to/project -o reports/

The implementation lives in src/vibecheck_trufflehog/trufflehog_runner.py, which
is standard-library only and can also be copied into another project on its own.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from vibecheck_trufflehog.trufflehog_runner import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
