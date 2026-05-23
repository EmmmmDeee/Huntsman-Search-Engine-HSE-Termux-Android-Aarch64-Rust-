---
name: Bug report
about: Something is broken or misbehaving
title: "bug: "
labels: bug
---

## What happened
<!-- A clear, concise description of the bug. -->

## Reproduce
<!-- Exact commands and inputs. -->

```sh
hse scan --kind ... --value ...
```

## Expected behaviour
<!-- What you thought should happen. -->

## Actual behaviour
<!-- What actually happened, including any error message. -->

## Environment

- HSE version: `hse --version` →
- OS / arch: `uname -srm` →
- Termux version (if applicable):
- Rust version: `rustc --version` →
- Install method: `install.sh` / manual `cargo install` / other

## Logs

<details><summary>Install log (<code>~/.cache/hse-install.log</code>)</summary>

```
<paste here>
```
</details>

<details><summary><code>hse doctor</code> output</summary>

```
<paste here>
```
</details>

<details><summary>Run with <code>RUST_LOG=debug</code></summary>

```
<paste here>
```
</details>
