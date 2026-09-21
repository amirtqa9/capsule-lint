# CapsuleLint

CapsuleLint checks a structured context handoff before another session relies on it. It validates the manifest, cross-references decisions and obligations, checks local evidence files and Markdown anchors, and reports Git revision or freshness concerns. It runs locally and never edits the capsule.

## Install

Requires Python 3.11 or newer. From this repository:

```sh
python3 -m pip install -e .
```

For YAML manifests, install `python3 -m pip install -e '.[yaml]'`. JSON works without the optional dependency.

## Use

```sh
capsule-lint schema > capsule.schema.json
capsule-lint check capsule.json --root .
capsule-lint check capsule.json --root . --format sarif --out lint.sarif
```

The manifest names a handoff document, source revision, decisions, obligations, and evidence. `--root` sets the boundary for local file references. The command exits with `0` when clear, `1` for lint errors, and `2` for invalid input. Add `--strict` to make warnings fail the check.

Run the tests with `PYTHONPATH=src python3 -m unittest discover -s tests -q`.
