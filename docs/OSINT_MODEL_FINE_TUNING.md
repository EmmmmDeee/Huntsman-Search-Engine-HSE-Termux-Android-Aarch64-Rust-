# Fine-tuning a Llama model for `hse analyze` / `hse-ai-daemon`

> **Scope note.** This is a guide for work you do **on your own GPU hardware**,
> entirely outside this repository's build. Nothing here is executed by, shipped
> in, or a dependency of the `hse`/`huntsman_search_engine` Rust crate — that
> crate's `Runtime AI-independence` invariant (`src/lib.rs`) means the
> deterministic scan/correlation engine carries no AI/ML dependency and never
> will. A model you fine-tune following this guide is just another GGUF file you
> hand to Ollama, exactly like any pre-trained model — `src/ai/` (`hse analyze`,
> `hse-ai-daemon`) doesn't know or care whether the model behind `--model <tag>`
> was fine-tuned or stock. See `README.md`'s "AI-Daemon Scan Analysis (opt-in)"
> section for how the finished model gets used.

## Why fine-tune at all

`hse analyze` already gets useful results from a stock instruct model via
prompt engineering alone (`src/ai/analysis.rs::build_prompt`) plus Ollama's
JSON-mode constraint (`"format": "json"` in `src/ai/ollama.rs::generate`). Both
of those keep working with a fine-tuned model — this isn't an either/or.
Fine-tuning is worth the effort specifically when a stock model, even with a
good prompt, still:

- drifts from the exact `{"summary": ..., "findings": [...]}` shape often
  enough that `analysis::parse_response` rejects a non-trivial fraction of
  responses (fails closed — see its own doc comment — so this shows up as
  outright errors, not silently-bad output);
  restates raw entity values as "findings" instead of synthesising *why*
  something matters (the exact failure mode `build_prompt`'s "not a
  re-statement of one entity's raw value" instruction targets);
- miscalibrates severity — everything comes back 80+, or nothing does, instead
  of tracking the rubric in the prompt;
  produces a good result on Llama 3.1 8B but you want that quality at 3B (or
  1B) size to run acceptably on the same modest hardware `hse` itself targets.

If a stock model already clears those bars for you, this guide buys you
nothing — don't fine-tune for its own sake.

## What "the task" actually is

Ground truth, so the training data matches what the deployed model will
actually be asked to do — read directly from the current source, not
paraphrased, since a schema drift here would make the whole fine-tune useless:

- **Input**: the full prompt `analysis::build_prompt(scan_id, entities)`
  builds — a fixed instruction block (role, the anti-exploitation constraint,
  the grounding/anti-hallucination instruction, the severity rubric, the
  requested JSON shape) followed by an entity list, each line
  `- {kind} = {value} (confidence {c_effective:.2})`, wrapped in
  `>>> BEGIN SCAN DATA >>> ... <<< END SCAN DATA <<<` markers. At most 200
  entities (`MAX_ENTITIES_IN_PROMPT`), each value capped at 200 chars
  (`MAX_VALUE_CHARS`). Entities are pre-redacted (`util::redact::redact_entities`)
  — credential-class values are already `[redacted]` and coordinates already
  coarsened by the time they reach the prompt, so don't train the model to
  expect (or reproduce) real secrets in its input.
- **Output**: raw text that `analysis::parse_response` parses as JSON matching
  exactly:
  ```json
  {"summary": "<one short paragraph>", "findings": [{"description": "<finding>", "severity": <0-100>}]}
  ```
  `findings` is capped at 5 (`MAX_FINDINGS`) on the Rust side regardless of
  what the model returns, and `severity` is clamped to `[0, 100]` — so a
  model that occasionally emits 6 findings or a severity of -5 is not fatal,
  but training it to already respect both bounds means less gets silently
  discarded/clamped away from what the model "meant."

## Prerequisites

- A GPU with enough VRAM for the base model you pick, e.g. roughly 8-12 GB for
  QLoRA on a 3B model, 16-24 GB for an 8B model (4-bit quantised base + LoRA
  adapter gradients — figures are approximate and vary by trainer/sequence
  length). None of this runs on the sandbox this repo's own CI/gate.sh uses.
- Python 3.10+, with:
  ```bash
  pip install -r scripts/finetune/requirements.txt
  ```
- [llama.cpp](https://github.com/ggml-org/llama.cpp) checked out and built, for
  the GGUF conversion + quantisation step at the end.
- Ollama installed on the machine that will actually *run* the finished model
  (may be the same machine, may be the Termux/Android device `hse` itself
  runs on).

## Base model choice

Any Llama-3.x instruct checkpoint works as a starting point; pick by what the
*deployment* target can run, since that's the binding constraint for an
on-device OSINT tool:

| Model | Rough use case |
|---|---|
| `meta-llama/Llama-3.2-1B-Instruct` | Fastest, least capable — only if the deployment device is very constrained. |
| `meta-llama/Llama-3.2-3B-Instruct` | Good default for a Termux/phone-class deployment target — matches this project's own "phone-safe" budget ethos. |
| `meta-llama/Llama-3.1-8B-Instruct` | Stronger baseline if the deployment machine (not necessarily the phone) has the headroom; still small enough to run comfortably on a desktop/laptop GPU or CPU via Ollama. |

All three are gated on Hugging Face under Meta's Llama license — accept the
license there before downloading. Nothing about this recipe is
model-specific beyond the base checkpoint name; swap in a different Llama
size without changing anything else below.

## Building the dataset

You almost certainly don't have thousands of hand-labelled `(prompt,
response)` pairs sitting around, so build the dataset from two sources:

**1. Real scan data, synthetic labels (bootstrapping via distillation).**
Run real scans, export them, and generate the *target* output with a stronger
model (a larger local Llama, or any other strong instruct model you have
access to) — this is standard practice for building small-model training
sets and is not the same thing as "training on the small model's own output."

```bash
# From a real completed scan:
hse export --scan-id <id> --format json --out scan_entities.json --redact
```

`--redact` only applies to the `json`/`csv`/`gexf` export formats — `report`
rejects it outright, because `report`'s nested scan-report shape embeds the
full `Entity` list (`crate::app::export::build_scan_report`'s
`"entities": entities`) without routing it through the redaction pass, so it
is the wrong export for this pipeline regardless of `--redact`. `--format
json` is also the format `analysis::build_prompt` itself is grounded in: each
entity object carries the same `c_effective` field the deployed model ranks
and displays by (`report` does not expose `c_effective` at all — only
`json`/`csv` do). `--redact` matters here for the same reason it matters
everywhere else exported data leaves the local machine (see `util::redact`)
— you don't want a training corpus that ever contained a real cleartext
credential, even transiently, on disk or in a training log.

**2. Synthetic entity lists, for coverage.** Real scans skew toward whatever
entity kinds your own OSINT footprint happens to produce. Generate synthetic
`(kind, value, confidence)` tuples spanning every `EntityKind` this crate
defines (`src/core/entity/mod.rs`) so the fine-tuned model has seen more than
just email/domain/URL-heavy examples.

A minimal data-prep script that turns exported scans into the training JSONL
format below — pure data transformation, no GPU needed, runs anywhere:
[`scripts/finetune/prepare_finetune_data.py`](../scripts/finetune/prepare_finetune_data.py).
Its `entity_lines`/`build_prompt` mirror `analysis::build_prompt`
(`src/ai/analysis.rs`) field-for-field, INCLUDING ranking and displaying by
each entity's `c_effective` — not the raw `confidence` field, which
`--format json` also exports but which the deployed model never ranks or
displays by:

```bash
python3 scripts/finetune/prepare_finetune_data.py \
    <scan_id> scan_entities.json teacher_response.txt train.jsonl
```

Run it once per `(scan_entities.json, teacher_response.txt)` pair, appending
to one growing `train.jsonl`. A few hundred diverse examples (varied
entity-kind mixes, varied exposure severity, some genuinely low-signal scans
so the model learns to say "nothing notable" rather than manufacturing a
finding) goes a long way further than a large but repetitive set.

Hold out ~10-15% of examples into a separate `eval.jsonl` — never trained on,
used only in the Evaluation step below.

## LoRA/QLoRA training recipe

[`scripts/finetune/train_lora.py`](../scripts/finetune/train_lora.py) — run
on a machine with a real GPU, from a directory containing `train.jsonl` and
`eval.jsonl`:

```bash
pip install -r scripts/finetune/requirements.txt
python3 scripts/finetune/train_lora.py
```

`r=16`/`alpha=32` and 3 epochs are reasonable starting points for a
few-hundred-example dataset on a 1B-8B model — raise `r` (32-64) if the model
underfits (still misses the JSON shape or the rubric after training), lower
the learning rate or epoch count if it overfits (verbatim-repeats training
examples, degrades on the held-out eval set).

## Evaluation

Before exporting anything, validate the fine-tuned model actually satisfies
the real contract — reusing the shape `analysis::parse_response` enforces,
not just eyeballing outputs. Run every held-out `eval.jsonl` prompt through
the fine-tuned model, write each raw response as one JSON-encoded line into
`eval_responses.jsonl`, then:

```bash
python3 scripts/finetune/validate_response.py eval_responses.jsonl
```

Its `validate()` mirrors every hard-reject rule `analysis::parse_response`
enforces (including that each finding's `description` must be a JSON
string, not just present — a check the shape validator now applies
symmetrically with the `severity` check next to it) and reports the
parse-success rate (should approach 100% — this is exactly what `"format":
"json"` plus fine-tuning together should make close to guaranteed). Separately,
its `diagnostics()` reports two things `parse_response` does NOT reject on —
it silently `.take(MAX_FINDINGS)`s and `.clamp(0, 100)`s instead — so a
response outside `[0, 5]` findings or `[0, 100]` severity still counts toward
the parse-success rate but is flagged as a `[warn]` line: informational
signal that the model hasn't yet learned bounds the Rust side quietly
enforces for it. Finish with a manual spot-check that severities track the
rubric (a corroborated cleartext credential should land 75+, not 20).

## Export to Ollama

```bash
# 1. Merge the LoRA adapter into the base model
python -c "
from peft import PeftModel
from transformers import AutoModelForCausalLM
base = AutoModelForCausalLM.from_pretrained('meta-llama/Llama-3.2-3B-Instruct')
merged = PeftModel.from_pretrained(base, './hse-analyze-lora/final').merge_and_unload()
merged.save_pretrained('./hse-analyze-merged')
"

# 2. Convert to GGUF (from your llama.cpp checkout)
python convert_hf_to_gguf.py ./hse-analyze-merged --outfile hse-analyze.gguf --outtype f16

# 3. Quantise for deployment size/speed (q4_K_M is a good phone-class default)
./llama-quantize hse-analyze.gguf hse-analyze-q4_k_m.gguf Q4_K_M
```

Copy [`scripts/finetune/Modelfile.example`](../scripts/finetune/Modelfile.example)
next to the quantised GGUF (adjust its `FROM` path if you renamed the file),
then:

```bash
ollama create hse-analyze -f Modelfile.example
```

Then use it exactly like any other model:

```bash
hse config feature.ai_daemon on
hse analyze --scan-id latest --model hse-analyze

# or for the background daemon:
HUNTSMAN_OLLAMA_MODEL=hse-analyze hse-ai-daemon
```

## Staying in scope

Everything in this guide happens on your own hardware, outside this repo's
build and CI. Nothing under `scripts/finetune/` becomes a Rust dependency,
nothing there runs in `scripts/gate.sh`, and the finished GGUF is just
another file Ollama serves — `src/ai/` treats it identically to any stock
model. `scripts/finetune/` stays Python/dev-tooling-only, matching how
`scripts/doc_coverage.sh` and `scripts/gate.sh` already live alongside the
crate without being part of it.
