"""Load Terraform files into simple Resource objects. Reads files only: nothing is deployed or contacted."""
import re
from dataclasses import dataclass, field
from pathlib import Path

import hcl2

REF_RE = re.compile(r"\b(aws_[a-z0-9_]+)\.([A-Za-z0-9_-]+)\b")


@dataclass
class Resource:
    kind: str            # "resource" or "provider"
    type: str            # e.g. "aws_s3_bucket"
    name: str            # e.g. "data"
    attrs: dict
    file: str
    comments: list[str] = field(default_factory=list)
    line: int = 1

    @property
    def address(self) -> str:
        return f"{self.type}.{self.name}" if self.kind == "resource" else f"provider.{self.name}"

    def get(self, key, default=None):
        return self.attrs.get(key, default)

    def blocks(self, key) -> list[dict]:
        value = self.attrs.get(key)
        if isinstance(value, dict):
            return [value]
        return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _clean(value):
    """python-hcl2 keeps literal quotes ('"private"'); strip them and drop parser bookkeeping keys."""
    if isinstance(value, str):
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1]
        if value.startswith("<<") and "\n" in value:  # heredoc: <<EOF\n...\nEOF
            body = value.split("\n", 1)[1]
            value = body.rsplit("\n", 1)[0] if "\n" in body else body
        return value
    if isinstance(value, list):
        return [_clean(v) for v in value]
    if isinstance(value, dict):
        return {_clean(k): _clean(v) for k, v in value.items() if k not in ("__is_block__", "__comments__", "__start_line__", "__end_line__")}
    return value


def _comments(attrs: dict) -> list[str]:
    return [c.get("value", "").strip() for c in attrs.get("__comments__", []) if isinstance(c, dict)]


def _line_of(text: str, pattern: str) -> int:
    m = re.search(pattern, text)
    return text.count("\n", 0, m.start()) + 1 if m else 1


def load_file(path: Path, root: Path | None = None) -> list[Resource]:
    text = path.read_text(encoding="utf-8")
    doc = hcl2.loads(text)
    shown = path.relative_to(root).as_posix() if root else path.name
    out = []
    for block in doc.get("resource", []):
        for rtype, items in block.items():
            for name, attrs in items.items():
                t, n = _clean(rtype), _clean(name)
                line = _line_of(text, rf'resource\s+"{re.escape(t)}"\s+"{re.escape(n)}"')
                out.append(Resource("resource", t, n, _clean(attrs), shown, _comments(attrs), line))
    for block in doc.get("provider", []):
        for ptype, attrs in block.items():
            t, clean = _clean(ptype), _clean(attrs)
            alias = clean.get("alias")
            line = _line_of(text, rf'alias\s*=\s*"{re.escape(alias)}"') if alias else _line_of(text, rf'provider\s+"{re.escape(t)}"')
            out.append(Resource("provider", t, f"{t}.{alias}" if alias else t, clean, shown, _comments(attrs), line))
    return out


def load_dir(path: Path) -> tuple[list[Resource], list[str]]:
    resources, errors = [], []
    files = [path] if path.is_file() else sorted(path.rglob("*.tf"))
    root = path if path.is_dir() else path.parent
    for f in files:
        try:
            resources.extend(load_file(f, root))
        except Exception as e:  # one malformed file shouldn't stop the scan
            errors.append(f"{f.name}: {e}")
    return resources, errors


def references(value) -> set[str]:
    """Resource addresses referenced anywhere inside a value, e.g. '${aws_s3_bucket.data.id}' -> aws_s3_bucket.data."""
    text = str(value)
    return {f"{t}.{n}" for t, n in REF_RE.findall(text)}


def truthy(value) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")
