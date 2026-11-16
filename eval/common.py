import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "dataset" / "sft_v1"
TRAIN_PATH = DATA_DIR / "sft_train.jsonl"
VAL_PATH = DATA_DIR / "sft_val.jsonl"

def load_rows(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f]