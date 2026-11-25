"""
The tools our demo assistant can use. They are FAKE and safe:
  read_file(name)     -> returns text of a file (from a dict or from agent/documents/)
  read_webpage(name)  -> same, meant for .html pages
  send_email(to,body) -> does NOT send anything; it only records the email in `outbox`

The evaluation checks `outbox` to see whether an attack made the AI "leak" something.
"""
from pathlib import Path

DOCS = Path(__file__).resolve().parent / "documents"

TOOL_SCHEMAS = [
    {"type": "function", "function": {
        "name": "read_file", "description": "Read a text file by name.",
        "parameters": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}}},
    {"type": "function", "function": {
        "name": "read_webpage", "description": "Read a saved web page (.html) by name.",
        "parameters": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}}},
    {"type": "function", "function": {
        "name": "send_email", "description": "Send an email.",
        "parameters": {"type": "object",
                       "properties": {"to": {"type": "string"}, "body": {"type": "string"}},
                       "required": ["to", "body"]}}},
]


class ToolBox:
    def __init__(self, files=None, docs_dir=DOCS):
        self.files = dict(files or {})          # virtual files (used by the evaluation)
        self.docs_dir = Path(docs_dir) if docs_dir else None
        self.outbox = []                        # every "sent" email lands here

    def _read(self, name: str) -> str:
        if name in self.files:
            return self.files[name]
        if self.docs_dir:
            p = (self.docs_dir / name).resolve()
            if p.parent == self.docs_dir.resolve() and p.is_file():
                return p.read_text(encoding="utf-8")
        return f"ERROR: file '{name}' not found"

    def execute(self, name: str, args: dict) -> str:
        args = args or {}
        if name in ("read_file", "read_webpage"):
            return self._read(str(args.get("name", "")))
        if name == "send_email":
            self.outbox.append({"to": str(args.get("to", "")), "body": str(args.get("body", ""))})
            return f"Email sent to {args.get('to')}."
        return f"ERROR: unknown tool '{name}'"
