"""
Evaluate original, baseline, trained, and reference code using score.py.

Inputs:
    Validation dataset and baseline/trained output JSONL files.

Processing:
    Scan each version and apply the team's grading checks.

Outputs:
    Overall and per-file-type pass rates printed to the terminal,
    plus detailed scores saved to a JSONL file.

Run from the repository root:
    python3 eval/report.py --limit 1
    python3 eval/report.py
"""

import argparse
import json
from pathlib import Path

from common import load_rows, VAL_PATH
from score import parse_prompt, scan, score_output, short

# Show the four systems in a consistent order.
SYSTEMS = ["original", "base", "trained", "reference"]

# Locate files relative to this script's eval/ folder.
EVAL_DIR = Path(__file__).resolve().parent


def load_outputs(path):
    """Read generated answers and organize them by validation index."""
    outputs = {}

    with open(path, encoding="utf-8") as f:
        for line in f:
            # Ignore blank lines.
            if not line.strip():
                continue

            row = json.loads(line)
            index = row["index"]

            # Reject duplicate indices and answers that are not text.
            if index in outputs:
                raise ValueError(f"Duplicate index {index} in {path}")
            if not isinstance(row["output"], str):
                raise ValueError(f"Output {index} must be text")

            outputs[index] = row["output"]

    return outputs


def show_rate(results):
    """Print the number passed, total evaluated, and pass percentage."""
    if not results:
        print("Not evaluated")
        return

    passed = sum(row["passed"] for row in results)
    total = len(results)
    rate = 100 * passed / total

    print(f"{passed}/{total} passed ({rate:.1f}%)")


def main():
    """Load answers, grade all four systems, and summarize the results."""

    # Allow input/output paths and a small test limit to be selected.
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--base", type=Path,
        default=EVAL_DIR / "outputs/base_outputs.jsonl"
    )
    parser.add_argument(
        "--trained", type=Path,
        default=EVAL_DIR / "outputs/trained_outputs.jsonl"
    )
    parser.add_argument(
        "--out", type=Path,
        default=EVAL_DIR / "results/report_scores.jsonl"
    )
    parser.add_argument(
        "--limit", type=int,
        help="Evaluate only the first N examples for a quick test"
    )
    args = parser.parse_args()

    # Use the validation dataset configured in common.py.
    rows = load_rows(VAL_PATH)

    if args.limit is not None and args.limit <= 0:
        parser.error("--limit must be positive")

    # Evaluate all rows unless a smaller test limit is provided.
    count = min(args.limit, len(rows)) if args.limit else len(rows)

    base_outputs = load_outputs(args.base)
    trained_outputs = load_outputs(args.trained)

    # Confirm both models have an answer for every selected example.
    for name, outputs in [
        ("base", base_outputs),
        ("trained", trained_outputs)
    ]:
        missing = [i for i in range(count) if i not in outputs]

        if missing:
            raise ValueError(f"{name} is missing indices: {missing}")

    # Prepare and validate every selected row before running scanners.
    examples = []

    for i, row in enumerate(rows[:count]):
        messages = row["messages"]

        # Select the user prompt while allowing a system message.
        user_messages = [
            message for message in messages
            if message["role"] == "user"
        ]

        if not user_messages or messages[-1]["role"] != "assistant":
            raise ValueError(f"Invalid conversation in row {i}")

        prompt = user_messages[-1]["content"]
        path, findings, original = parse_prompt(prompt)

        # Require findings, original code, and a safe relative file path.
        if (
            not path
            or not findings
            or "FILE CONTENT:\n" not in prompt
            or Path(path).is_absolute()
            or ".." in Path(path).parts
        ):
            raise ValueError(f"Could not parse row {i} safely")

        # The final assistant message contains the reference answer.
        reference = messages[-1]["content"]
        examples.append((i, path, findings, original, reference))

    results = []
    unverifiable = 0

    for i, path, findings, original, reference in examples:
        # Reuse the original scan as the comparison for all systems.
        orig_rules = scan(original, path)

        # Check whether scanners detect any listed issue in the original.
        listed = {short(finding["rule"]) for finding in findings}
        detectable = bool(listed & orig_rules)

        if not detectable:
            unverifiable += 1

        # Group extensionless Dockerfiles under a recognizable label.
        filename = Path(path).name

        if filename.lower() == "dockerfile":
            file_type = "Dockerfile"
        else:
            file_type = Path(path).suffix.lower() or filename

        # Compare all four versions of this same validation example.
        answers = {
            "original": original,
            "base": base_outputs[i],
            "trained": trained_outputs[i],
            "reference": reference
        }

        for system, answer in answers.items():
            # Avoid scanning again when an answer equals the original.
            answer_rules = (
                orig_rules if answer == original
                else scan(answer, path)
            )

            # Apply the existing team's checks without changing them.
            passed, reasons = score_output(
                path, findings, original,
                orig_rules, answer, answer_rules
            )

            # Preserve scores and failure reasons for later review.
            results.append({
                "index": i,
                "system": system,
                "path": path,
                "file_type": file_type,
                "passed": bool(passed),
                "reasons": reasons,
                "listed_issue_detectable": detectable
            })

        print(f"Completed {i + 1}/{count}: {path}", flush=True)

    # Save one grading record per line, creating the folder if needed.
    args.out.parent.mkdir(parents=True, exist_ok=True)

    with open(args.out, "w", encoding="utf-8") as f:
        for result in results:
            f.write(json.dumps(result) + "\n")

    print("\nEVALUATION RESULTS")
    print("Validation examples evaluated:", count)

    for system in SYSTEMS:
        # Calculate this system's overall pass rate.
        system_results = [
            row for row in results
            if row["system"] == system
        ]

        print(f"\n{system}:")
        show_rate(system_results)

        # Calculate separate pass rates for each file type.
        file_types = sorted({
            row["file_type"] for row in system_results
        })

        for file_type in file_types:
            type_results = [
                row for row in system_results
                if row["file_type"] == file_type
            ]

            print(f"  {file_type}: ", end="")
            show_rate(type_results)

    # Flag examples whose listed issues were not detected initially.
    print(
        "\nExamples where scanners did not detect any listed "
        "issue in the original:",
        unverifiable
    )
    print("Saved detailed scores to:", args.out)


# Run the report only when this file is executed directly.
if __name__ == "__main__":
    main()
