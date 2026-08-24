#!/usr/bin/env python3
"""QLoRA fine-tune for hse analyze / hse-ai-daemon.

    python3 scripts/finetune/train_lora.py

Run on a machine with a real GPU — see docs/OSINT_MODEL_FINE_TUNING.md's
Prerequisites section for VRAM ballparks. Dev-tooling only: nothing here is a
dependency of the hse/huntsman_search_engine Rust crate; none of it runs in
scripts/gate.sh. Expects train.jsonl/eval.jsonl already built via
prepare_finetune_data.py in the current directory.
"""
import torch
from datasets import load_dataset
from peft import LoraConfig
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from trl import SFTConfig, SFTTrainer

BASE_MODEL = "meta-llama/Llama-3.2-3B-Instruct"  # swap per the guide's base-model table

bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16,
    bnb_4bit_use_double_quant=True,
)

tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL, quantization_config=bnb_config, device_map="auto"
)

lora_config = LoraConfig(
    r=16,
    lora_alpha=32,
    lora_dropout=0.05,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    task_type="CAUSAL_LM",
)

dataset = load_dataset("json", data_files={"train": "train.jsonl", "eval": "eval.jsonl"})

sft_config = SFTConfig(
    output_dir="./hse-analyze-lora",
    per_device_train_batch_size=2,
    gradient_accumulation_steps=8,
    num_train_epochs=3,
    learning_rate=2e-4,
    lr_scheduler_type="cosine",
    warmup_ratio=0.03,
    logging_steps=10,
    eval_strategy="steps",
    eval_steps=50,
    save_strategy="epoch",
    bf16=True,
    max_seq_length=4096,  # the prompt can be long at MAX_ENTITIES_IN_PROMPT=200
    packing=False,        # keep examples un-packed: each prompt's entity list
                           # is semantically self-contained, and packing can
                           # blur the >>> BEGIN/END SCAN DATA <<< boundaries
                           # across unrelated examples
)

trainer = SFTTrainer(
    model=model,
    args=sft_config,
    train_dataset=dataset["train"],
    eval_dataset=dataset["eval"],
    peft_config=lora_config,
)
trainer.train()
trainer.save_model("./hse-analyze-lora/final")
