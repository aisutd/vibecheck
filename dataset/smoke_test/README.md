# Smoke test data (practice only)
Used for the first practice fine-tune. This is NOT the real dataset.
- smoke_train.jsonl: 477 examples. smoke_val.jsonl: 25 examples.
- Each line: {"messages": [{"role": "user", ...}, {"role": "assistant", ...}]}
- Hand-picked for variety (capped per file type, rule and project), so the mix
  does not match the real dataset.
- Finding messages in the prompts are cut at about 200 characters. Known issue.
- Don't train a real model on this.