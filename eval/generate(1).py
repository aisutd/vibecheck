"""Harness Piece A: baseline or adapter generation. Requires a CUDA GPU.

Run from the repository root:
  python eval/generate.py --data dataset/sft_r3/sft_val.jsonl --out eval/outputs/base_outputs.jsonl
  python eval/generate.py --adapter training/checkpoints/vibecheck-c-adapter --data dataset/sft_r3/sft_val.jsonl --out eval/outputs/trained_outputs.jsonl
"""
import argparse
import json
import math
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adapter', help='Extracted adapter folder; omit for baseline')
    parser.add_argument('--data', type=Path, required=True, help='Input dataset JSONL')
    parser.add_argument('--out', type=Path, required=True, help='JSONL path in eval/outputs/')
    parser.add_argument('--num-samples', type=int, default=1)
    parser.add_argument('--temperature', type=float, default=0.0)
    parser.add_argument('--start', type=int, default=0, help='First row index, inclusive')
    parser.add_argument('--end', type=int, help='Last row boundary, exclusive; defaults to dataset size')
    args = parser.parse_args()
    if args.num_samples < 1:
        parser.error('--num-samples must be at least 1')
    if not math.isfinite(args.temperature) or args.temperature < 0:
        parser.error('--temperature must be finite and nonnegative')

    generation_options = {'do_sample': args.temperature > 0}
    if args.temperature > 0:
        generation_options['temperature'] = args.temperature

    # Resolve outputs relative to the repository, even if run from another folder.
    repo_root = Path(__file__).resolve().parent.parent
    output_dir = (repo_root / 'eval' / 'outputs').resolve()
    out_path = args.out if args.out.is_absolute() else repo_root / args.out
    out_path = out_path.resolve()
    if not out_path.is_relative_to(output_dir) or out_path.suffix != '.jsonl':
        parser.error('--out must be a .jsonl path inside eval/outputs/')
    if out_path.exists():
        parser.error(f'Output already exists; choose a new --out path: {out_path}')
    data_path = args.data if args.data.is_absolute() else repo_root / args.data
    with data_path.open(encoding='utf-8') as source:
        rows = [json.loads(line) for line in source if line.strip()]
    if not rows:
        parser.error('Input dataset is empty')
    end = len(rows) if args.end is None else args.end
    if not 0 <= args.start < end <= len(rows):
        parser.error(f'Require 0 <= --start < --end <= {len(rows)}')
    selected_rows = rows[args.start:end]
    for i, row in enumerate(selected_rows, start=args.start):
        messages = row['messages']
        if len(messages) < 2 or messages[-1]['role'] != 'assistant':
            parser.error(f'Row {i} must end with a reference assistant answer')
        if messages[-2]['role'] != 'user' or 'FILE CONTENT:\n' not in messages[-2]['content']:
            parser.error(f'Row {i} must have a user prompt with FILE CONTENT marker')

    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig, set_seed

    if not torch.cuda.is_available():
        parser.error('This script requires a CUDA GPU, such as a Colab T4')
    set_seed(42)
    model_name = 'Qwen/Qwen2.5-Coder-1.5B-Instruct'
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    quant_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type='nf4',
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=torch.float16,
    )
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        quantization_config=quant_config,
        device_map={'': 0},
        dtype=torch.float16,
    )
    if args.adapter:
        from peft import PeftModel
        adapter_path = Path(args.adapter)
        if not adapter_path.is_absolute():
            adapter_path = repo_root / adapter_path
        model = PeftModel.from_pretrained(model, str(adapter_path))
    model.eval()
    model.config.use_cache = True
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Hide the reference answer; preserve the raw generated text.
    with out_path.open('x', encoding='utf-8') as destination:
        for i, row in enumerate(selected_rows, start=args.start):
            prompt_messages = row['messages'][:-1]
            original_file = prompt_messages[-1]['content'].split('FILE CONTENT:\n', 1)[1]
            original_tokens = len(tokenizer.encode(original_file, add_special_tokens=False))
            budget = math.ceil(1.3 * original_tokens) + 100
            inputs = tokenizer.apply_chat_template(
                prompt_messages,
                tokenize=True,
                add_generation_prompt=True,
                return_dict=True,
                return_tensors='pt',
            ).to('cuda')
            for sample_id in range(args.num_samples):
                with torch.inference_mode(), torch.autocast('cuda', dtype=torch.float16):
                    output = model.generate(
                        **inputs,
                        **generation_options,
                        max_new_tokens=budget,
                        pad_token_id=tokenizer.eos_token_id,
                    )
                answer_ids = output[0, inputs['input_ids'].shape[1]:]
                answer = tokenizer.decode(answer_ids, skip_special_tokens=True)
                record = {'index': i, 'output': answer}
                if args.num_samples > 1:
                    record['sample_id'] = sample_id
                destination.write(json.dumps(record) + '\n')
                destination.flush()
            print(f'Completed {i - args.start + 1}/{len(selected_rows)}', flush=True)
    print(f'Saved outputs to: {out_path}')


if __name__ == '__main__':
    main()
