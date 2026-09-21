"""Command-line interface and stable report renderers."""

from __future__ import annotations

import argparse
from bisect import bisect_right
from dataclasses import replace
import hashlib
import json
from importlib.resources import files
from pathlib import Path
import sys
from typing import Any

from .core import Diagnostic, Resolver, RULE_VERSION, lint


def _source_lines(raw: str, name: str) -> dict[str, int]:
    """Map JSON/YAML value paths to their starting line in the manifest."""
    if name.lower().endswith((".yaml", ".yml")):
        import yaml

        result: dict[str, int] = {}

        def walk(node: Any, path: str) -> None:
            result[path] = node.start_mark.line + 1
            if isinstance(node, yaml.MappingNode):
                for key, value in node.value:
                    walk(value, f"{path}.{key.value}")
            elif isinstance(node, yaml.SequenceNode):
                for index, value in enumerate(node.value):
                    walk(value, f"{path}[{index}]")

        root = yaml.compose(raw)
        if root is not None:
            walk(root, "$")
        return result

    decoder = json.JSONDecoder()
    newline_indexes = [index for index, char in enumerate(raw) if char == "\n"]
    result: dict[str, int] = {}

    def skip(index: int) -> int:
        while index < len(raw) and raw[index].isspace():
            index += 1
        return index

    def walk(index: int, path: str) -> int:
        index = skip(index)
        result[path] = bisect_right(newline_indexes, index - 1) + 1
        if raw[index] == "{":
            index = skip(index + 1)
            while raw[index] != "}":
                key, index = decoder.raw_decode(raw, index)
                index = skip(index)
                index = walk(index + 1, f"{path}.{key}")
                index = skip(index)
                if raw[index] == ",":
                    index = skip(index + 1)
                else:
                    break
            return index + 1
        if raw[index] == "[":
            index = skip(index + 1)
            item = 0
            while raw[index] != "]":
                index = walk(index, f"{path}[{item}]")
                item += 1
                index = skip(index)
                if raw[index] == ",":
                    index = skip(index + 1)
                else:
                    break
            return index + 1
        _, end = decoder.raw_decode(raw, index)
        return end

    walk(0, "$")
    return result


def _attach_lines(diagnostics: list[Diagnostic], lines: dict[str, int]) -> list[Diagnostic]:
    located = []
    for diagnostic in diagnostics:
        path = diagnostic.location
        while path not in lines and path != "$":
            path = path.rsplit(".", 1)[0] if "." in path else "$"
            if path not in lines and "[" in path:
                path = path.rsplit("[", 1)[0]
        located.append(replace(diagnostic, line=lines.get(path)))
    return located


def _load_data(raw: str, name: str) -> Any:
    if name.lower().endswith((".yaml", ".yml")):
        try:
            import yaml
        except ImportError as exc:
            raise ValueError("YAML input requires pip install 'capsule-lint[yaml]'") from exc
        try:
            return yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise ValueError(f"invalid YAML: {exc}") from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc


def _report(diagnostics: list[Diagnostic], input_hash: str) -> dict[str, Any]:
    return {"schema_version": 1, "rule_version": RULE_VERSION,
            "input_hash": f"sha256:{input_hash}",
            "diagnostics": [d.to_dict() for d in diagnostics]}


def _render_text(diagnostics: list[Diagnostic], source: str = "capsule.json") -> str:
    if not diagnostics:
        return "CapsuleLint: no issues found\n"
    lines = []
    for d in diagnostics:
        suffix = f" Fix: {d.suggestion}" if d.suggestion else ""
        position = f"{source}:{d.line}: " if d.line is not None else ""
        lines.append(f"{position}{d.location}: {d.severity} {d.code}: {d.message}{suffix}")
    return "\n".join(lines) + "\n"


def _render_sarif(diagnostics: list[Diagnostic], source: str = "capsule.json") -> str:
    rules = sorted({d.code for d in diagnostics})
    data = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "CapsuleLint", "version": RULE_VERSION,
                                "rules": [{"id": code} for code in rules]}},
            "results": [{
                "ruleId": d.code,
                "level": "error" if d.severity == "error" else "warning",
                "message": {"text": d.message},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": source},
                                                     "region": {"startLine": d.line or 1}},
                               "logicalLocations": [{"fullyQualifiedName": d.location}]}],
                "properties": {"location": d.location, "suggestion": d.suggestion,
                               "related_locations": list(d.related_locations)},
            } for d in diagnostics],
        }],
    }
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="capsule-lint")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("schema", help="print the v1 JSON Schema")
    check = sub.add_parser("check", help="validate a capsule manifest")
    check.add_argument("capsule", help="JSON/YAML path or - for JSON stdin")
    check.add_argument("--root", type=Path, help="root for document and evidence references")
    check.add_argument("--profile", type=Path, help="JSON profile with severity and freshness policy")
    check.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    check.add_argument("--out", type=Path)
    check.add_argument("--strict", action="store_true", help="fail on warnings too")
    check.add_argument("--allow-external", action="store_true", help="allow references outside root")
    args = parser.parse_args(argv)
    if args.command == "schema":
        print(files("capsule_lint").joinpath("schema.json").read_text(), end="")
        return 0
    try:
        if args.capsule == "-":
            raw = sys.stdin.read()
            root = args.root or Path.cwd()
        else:
            path = Path(args.capsule).resolve()
            raw = path.read_text(encoding="utf-8")
            root = args.root or path.parent
        capsule = _load_data(raw, args.capsule)
        if not isinstance(capsule, dict):
            raise ValueError("manifest must be an object")
        profile = {}
        if args.profile:
            profile = _load_data(args.profile.read_text(encoding="utf-8"), args.profile.name)
            if not isinstance(profile, dict):
                raise ValueError("profile must be an object")
            severity = profile.get("severity", {})
            if not isinstance(severity, dict) or any(v not in ("error", "warning", "off") for v in severity.values()):
                raise ValueError("profile severity values must be error, warning, or off")
            sections = profile.get("required_sections", [])
            if not isinstance(sections, list) or any(x not in ("decisions", "obligations", "evidence") for x in sections):
                raise ValueError("required_sections must list decisions, obligations, or evidence")
            age = profile.get("max_evidence_age_days", 0)
            if isinstance(age, bool) or not isinstance(age, (int, float)) or age < 0:
                raise ValueError("max_evidence_age_days must be nonnegative")
        diagnostics = lint(capsule, Resolver(root, args.allow_external), profile)
        diagnostics = _attach_lines(diagnostics, _source_lines(raw, args.capsule))
        if args.format == "json":
            output = json.dumps(_report(diagnostics, hashlib.sha256(raw.encode()).hexdigest()),
                                indent=2, sort_keys=True) + "\n"
        elif args.format == "sarif":
            output = _render_sarif(diagnostics, args.capsule)
        else:
            output = _render_text(diagnostics, args.capsule)
        if args.out:
            args.out.write_text(output, encoding="utf-8")
        else:
            sys.stdout.write(output)
        return 1 if any(d.severity == "error" or args.strict for d in diagnostics) else 0
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"capsule-lint: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
