"""Pure-ish rule engine with a confined local-file resolver."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import html
import hashlib
from pathlib import Path
import re
import subprocess
from typing import Any, Mapping
from urllib.parse import unquote, urlparse

RULE_VERSION = "2"
SEVERITY_ORDER = {"error": 0, "warning": 1}


@dataclass(frozen=True)
class Diagnostic:
    code: str
    severity: str
    message: str
    location: str
    suggestion: str = ""
    related_locations: tuple[str, ...] = ()
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Resolver:
    root: Path
    allow_external: bool = False

    def resolve(self, ref: str) -> Path:
        # A :line suffix is an anchor, not part of the filesystem path.
        path_part = re.sub(r":\d+(?::\d+)?$", "", ref)
        if "#" in path_part and Path(path_part.split("#", 1)[0]).suffix.lower() in (".md", ".markdown"):
            path_part = path_part.split("#", 1)[0]
        candidate = (self.root / path_part).resolve()
        root = self.root.resolve()
        if not self.allow_external and not candidate.is_relative_to(root):
            raise ValueError("path escapes configured root")
        return candidate


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result if result.tzinfo else None
    except ValueError:
        return None


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _markdown_fragment(ref: str) -> str | None:
    """Return a Markdown fragment, keeping literal # in other filenames intact."""
    if "#" not in ref:
        return None
    path, fragment = ref.split("#", 1)
    return unquote(fragment) if Path(path).suffix.lower() in (".md", ".markdown") else None


def _heading_slug(title: str) -> str:
    title = re.sub(r"\[([^]]+)\]\([^)]+\)", r"\1", title)
    title = re.sub(r"<[^>]*>", "", title)
    title = html.unescape(title).lower()
    title = "".join(char for char in title if char.isalnum() or char in " _-\t")
    return re.sub(r"\s+", "-", title.strip())


def _markdown_anchors(path: Path) -> set[str]:
    """Collect heading slugs and explicit HTML IDs outside fenced code."""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    anchors: set[str] = set()
    counts: dict[str, int] = {}
    fence_char: str | None = None
    fence_width = 0
    previous = ""
    for line in lines:
        fence = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", line)
        if fence:
            marker = fence.group(1)
            if fence_char is None:
                fence_char, fence_width = marker[0], len(marker)
            elif marker[0] == fence_char and len(marker) >= fence_width and not fence.group(2).strip():
                fence_char = None
            previous = ""
            continue
        if fence_char is not None:
            continue
        for explicit in re.findall(r'<a\s+[^>]*?id\s*=\s*["\']([^"\']+)["\'][^>]*>', line, re.I):
            anchors.add(explicit)
        heading = re.match(r"^ {0,3}#{1,6}\s+(.+?)(?:\s+#+\s*)?$", line)
        if heading:
            title = heading.group(1)
        elif re.match(r"^ {0,3}(?:=+|-+)\s*$", line) and previous.strip():
            title = previous.strip()
        else:
            previous = line
            continue
        base = _heading_slug(title)
        if base:
            count = counts.get(base, 0)
            anchors.add(base if count == 0 else f"{base}-{count}")
            counts[base] = count + 1
        previous = ""
    return anchors


def _git_revision_state(root: Path, source: str, evidence: str) -> str:
    """Return equal, older, different, or unknown without assuming a Git checkout."""
    def run(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["git", "-C", str(root), *args], capture_output=True,
                              text=True, timeout=5, check=False)
    try:
        if run("rev-parse", "--is-inside-work-tree").stdout.strip() != "true":
            return "unknown"
        source_sha = run("rev-parse", "--verify", f"{source}^{{commit}}")
        evidence_sha = run("rev-parse", "--verify", f"{evidence}^{{commit}}")
        if source_sha.returncode or evidence_sha.returncode:
            return "unknown"
        if source_sha.stdout.strip() == evidence_sha.stdout.strip():
            return "equal"
        ancestor = run("merge-base", "--is-ancestor", evidence_sha.stdout.strip(), source_sha.stdout.strip())
        return "older" if ancestor.returncode == 0 else "different"
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"


def _git_file_state(root: Path, source: str, evidence: str, path: Path) -> str:
    """Compare a confined file's Git blob at two resolvable commits.

    An unavailable checkout, untracked evidence at its recorded revision, or a
    path outside the checkout yields unknown rather than a freshness claim.
    """
    def run(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["git", "-C", str(root), *args], capture_output=True,
                              text=True, timeout=5, check=False)

    try:
        top_result = run("rev-parse", "--show-toplevel")
        if top_result.returncode:
            return "unknown"
        top = Path(top_result.stdout.strip()).resolve()
        relative = path.resolve().relative_to(top).as_posix()
        source_result = run("rev-parse", "--verify", f"{source}^{{commit}}")
        evidence_result = run("rev-parse", "--verify", f"{evidence}^{{commit}}")
        if source_result.returncode or evidence_result.returncode:
            return "unknown"
        old_sha = evidence_result.stdout.strip()
        new_sha = source_result.stdout.strip()
        old_blob = run("rev-parse", "--verify", f"{old_sha}:{relative}")
        if old_blob.returncode:
            return "unknown"
        old_type = run("cat-file", "-t", old_blob.stdout.strip())
        if old_type.returncode or old_type.stdout.strip() != "blob":
            return "unknown"
        new_blob = run("rev-parse", "--verify", f"{new_sha}:{relative}")
        if new_blob.returncode:
            return "missing"
        new_type = run("cat-file", "-t", new_blob.stdout.strip())
        if new_type.returncode or new_type.stdout.strip() != "blob":
            return "missing"
        return "same" if old_blob.stdout.strip() == new_blob.stdout.strip() else "changed"
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return "unknown"


def lint(capsule: Mapping[str, Any], resolver: Resolver, profile: Mapping[str, Any] | None = None) -> list[Diagnostic]:
    """Return stable diagnostics. Invalid input remains a diagnostic, never a crash."""
    profile = profile or {}
    findings: list[Diagnostic] = []

    def add(code: str, severity: str, message: str, location: str, suggestion: str = "",
            related: tuple[str, ...] = ()) -> None:
        override = profile.get("severity", {})
        if isinstance(override, dict):
            severity = override.get(code, severity)
        if severity != "off":
            findings.append(Diagnostic(code, severity, message, location, suggestion, related))

    if not isinstance(capsule, dict):
        return [Diagnostic("CL001", "error", "manifest must be an object", "$")]
    if capsule.get("schema_version") != 1:
        add("CL001", "error", "unsupported schema_version; expected 1", "$.schema_version")
    for field in ("capsule_id", "source_revision", "document", "summary"):
        if not _nonempty(capsule.get(field)):
            add("CL002", "error", f"{field} is required and must be nonblank", f"$.{field}")
    if _timestamp(capsule.get("created_at")) is None:
        add("CL003", "error", "created_at must be an ISO 8601 timestamp with timezone", "$.created_at")
    sections: dict[str, list[Any]] = {}
    for name in ("decisions", "obligations", "evidence"):
        value = capsule.get(name)
        if not isinstance(value, list):
            add("CL004", "error", f"{name} must be an array", f"$.{name}")
            value = []
        sections[name] = value
    for name in ("assumptions", "dependencies"):
        if name in capsule and not isinstance(capsule[name], list):
            add("CL004", "error", f"{name} must be an array", f"$.{name}")
    required = profile.get("required_sections", [])
    if isinstance(required, list):
        for section in required:
            if section in sections and not sections[section]:
                add("CL005", "error", f"{section} is required by profile", f"$.{section}")

    document = capsule.get("document")
    if _nonempty(document):
        try:
            resolved = resolver.resolve(document)
            if not resolved.is_file():
                add("CL201", "error", "handoff document does not exist", "$.document")
        except ValueError:
            add("CL202", "error", "handoff document escapes configured root", "$.document")

    indexed: dict[str, dict[str, str]] = {name: {} for name in sections}
    for name, items in sections.items():
        for index, item in enumerate(items):
            location = f"$.{name}[{index}]"
            if not isinstance(item, dict):
                add("CL006", "error", "record must be an object", location)
                continue
            record_id = item.get("id")
            if not _nonempty(record_id):
                add("CL007", "error", "record id is required", f"{location}.id")
            elif record_id in indexed[name]:
                add("CL101", "error", f"duplicate {name} id: {record_id}", f"{location}.id",
                    related=(indexed[name][record_id],))
            else:
                indexed[name][record_id] = location
            required_text = {"decisions": "statement", "obligations": "description", "evidence": "ref"}[name]
            if not _nonempty(item.get(required_text)):
                add("CL008", "error", f"{required_text} is required", f"{location}.{required_text}")
            if name == "decisions":
                if item.get("status") not in ("active", "superseded"):
                    add("CL009", "error", "invalid decision status", f"{location}.status")
            elif name == "obligations":
                if item.get("status") not in ("open", "blocked", "done"):
                    add("CL009", "error", "invalid obligation status", f"{location}.status")
            else:
                if item.get("type") not in ("file", "url", "command", "test"):
                    add("CL009", "error", "invalid evidence type", f"{location}.type")
                if not _nonempty(item.get("revision")):
                    add("CL010", "error", "evidence revision is required", f"{location}.revision")
                if _timestamp(item.get("captured_at")) is None:
                    add("CL003", "error", "captured_at must be an ISO 8601 timestamp with timezone", f"{location}.captured_at")
            if name != "evidence":
                ids = item.get("evidence_ids")
                if not isinstance(ids, list) or any(not _nonempty(x) for x in ids):
                    add("CL011", "error", "evidence_ids must be an array of nonblank IDs", f"{location}.evidence_ids")

    evidence_ids = indexed["evidence"]
    for name in ("decisions", "obligations"):
        for index, item in enumerate(sections[name]):
            if not isinstance(item, dict):
                continue
            location = f"$.{name}[{index}]"
            ids = item.get("evidence_ids")
            if isinstance(ids, list):
                for evidence_id in ids:
                    if _nonempty(evidence_id) and evidence_id not in evidence_ids:
                        add("CL102", "error", f"unknown evidence id: {evidence_id}", f"{location}.evidence_ids")
            if name == "obligations":
                status = item.get("status")
                if status == "open" and (not _nonempty(item.get("owner")) or not _nonempty(item.get("next_action"))):
                    add("CL104", "error", "open obligation needs owner and next_action", location)
                if status == "blocked" and not _nonempty(item.get("blocker")):
                    add("CL302", "error", "blocked obligation needs blocker", location)
                if status == "done" and not ids:
                    add("CL301", "error", "done obligation needs completion evidence", location)

    decisions = {item.get("id"): item for item in sections["decisions"] if isinstance(item, dict) and _nonempty(item.get("id"))}
    active_topics: dict[str, str] = {}
    for index, item in enumerate(sections["decisions"]):
        if not isinstance(item, dict):
            continue
        location = f"$.decisions[{index}]"
        supersedes = item.get("supersedes")
        if supersedes and supersedes not in decisions:
            add("CL103", "error", f"unknown superseded decision: {supersedes}", f"{location}.supersedes")
        topic = item.get("topic_key")
        if item.get("status") == "active" and _nonempty(topic):
            if topic in active_topics:
                add("CL300", "error", f"duplicate active topic_key: {topic}", f"{location}.topic_key",
                    related=(active_topics[topic],))
            else:
                active_topics[topic] = f"{location}.topic_key"
    visited: set[str] = set()
    active: set[str] = set()

    def visit(decision_id: str) -> None:
        if decision_id in active:
            add("CL105", "error", f"supersedes cycle includes {decision_id}", indexed["decisions"].get(decision_id, "$.decisions"))
            return
        if decision_id in visited:
            return
        visited.add(decision_id)
        active.add(decision_id)
        target = decisions[decision_id].get("supersedes")
        if target in decisions:
            visit(target)
        active.remove(decision_id)

    for decision_id in decisions:
        visit(decision_id)

    source_revision = capsule.get("source_revision")
    max_age = profile.get("max_evidence_age_days")
    for index, item in enumerate(sections["evidence"]):
        if not isinstance(item, dict):
            continue
        location = f"$.evidence[{index}]"
        kind, ref = item.get("type"), item.get("ref")
        evidence_path: Path | None = None
        if kind == "url" and _nonempty(ref):
            parsed = urlparse(ref)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                add("CL203", "error", "evidence URL must be absolute HTTP(S)", f"{location}.ref")
        if kind == "file" and _nonempty(ref):
            try:
                path = resolver.resolve(ref)
                evidence_path = path
                if not path.is_file():
                    add("CL201", "error", "evidence file does not exist", f"{location}.ref")
                else:
                    expected = item.get("content_hash")
                    if expected:
                        actual = hashlib.sha256(path.read_bytes()).hexdigest()
                        if expected.removeprefix("sha256:").lower() != actual:
                            add("CL204", "error", "evidence content_hash differs from file", f"{location}.content_hash")
                    match = re.search(r":(\d+)(?::\d+)?$", ref)
                    if match:
                        with path.open("rb") as evidence_file:
                            line_count = sum(1 for _ in evidence_file)
                        if not 1 <= int(match.group(1)) <= line_count:
                            add("CL205", "warning", "evidence line anchor is outside file", f"{location}.ref")
                    fragment = _markdown_fragment(ref)
                    if fragment is not None and fragment not in _markdown_anchors(path):
                        add("CL210", "error", f"Markdown anchor does not exist: #{fragment}", f"{location}.ref")
            except ValueError:
                add("CL202", "error", "evidence path escapes configured root", f"{location}.ref")
            except OSError as exc:
                add("CL206", "error", f"cannot read evidence file: {exc.strerror}", f"{location}.ref")
        revision = item.get("revision")
        if _nonempty(source_revision) and _nonempty(revision) and revision != source_revision:
            state = _git_revision_state(resolver.root, source_revision, revision)
            if state == "older":
                add("CL207", "warning", "evidence was recorded at an older revision", f"{location}.revision")
                if kind == "file" and evidence_path is not None:
                    file_state = _git_file_state(resolver.root, source_revision, revision, evidence_path)
                    if file_state == "missing":
                        add("CL211", "error", "evidence file is absent at source_revision", f"{location}.ref")
                    elif file_state == "changed":
                        add("CL212", "warning", "evidence file changed since evidence revision", f"{location}.ref")
            elif state == "different":
                add("CL208", "warning", "evidence revision is not an ancestor of source revision", f"{location}.revision")
        captured = _timestamp(item.get("captured_at"))
        if captured and isinstance(max_age, (int, float)) and not isinstance(max_age, bool) and max_age >= 0:
            age_days = (datetime.now(timezone.utc) - captured).total_seconds() / 86400
            if age_days > max_age:
                add("CL209", "warning", f"evidence exceeds {max_age:g} day age limit", f"{location}.captured_at")
    return sorted(findings, key=lambda d: (SEVERITY_ORDER.get(d.severity, 2), d.code, d.location, d.message))
