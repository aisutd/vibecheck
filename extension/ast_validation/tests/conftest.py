import sys
from pathlib import Path

# Make `import ast_validation` work when pytest is run from anywhere.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
