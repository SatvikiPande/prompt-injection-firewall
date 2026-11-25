"""
STEP 4 (Layer 3): tool-call policy.

Before the agent runs any tool, we check the call against policy.yaml:
  1. Is the tool on the allow-list?
  2. Are the arguments valid (checked with Pydantic)?
  3. Extra rules that depend on "tainted" (untrusted content already seen):
       - sensitive files cannot be read
       - emails may only go to trusted domains, or to an address the user typed
"""
import re
from pathlib import Path

import yaml
from pydantic import BaseModel, ValidationError


class ReadFileArgs(BaseModel):
    name: str


class SendEmailArgs(BaseModel):
    to: str
    body: str = ""


ARG_MODELS = {"read_file": ReadFileArgs, "read_webpage": ReadFileArgs, "send_email": SendEmailArgs}
_EMAIL_RE = re.compile(r"^[\w.+-]+@([\w-]+(?:\.[\w-]+)+)$")


class Policy:
    def __init__(self, cfg: dict):
        self.cfg = cfg or {}
        self.default = self.cfg.get("default", "deny")
        self.tools = self.cfg.get("tools", {})

    @classmethod
    def load(cls, path):
        return cls(yaml.safe_load(Path(path).read_text(encoding="utf-8")))

    def check(self, tool: str, args: dict, tainted: bool, approved=()):
        """Return (allowed: bool, reason: str)."""
        spec = self.tools.get(tool)
        if spec is None:
            return (self.default == "allow", f"tool '{tool}' is not in the policy")
        if not spec.get("allow", False):
            return False, f"tool '{tool}' is disabled"

        model = ARG_MODELS.get(tool)
        try:
            parsed = model(**(args or {})).model_dump() if model else dict(args or {})
        except (ValidationError, TypeError):
            return False, f"invalid arguments for '{tool}'"

        if tool in ("read_file", "read_webpage"):
            return self._check_file(spec, parsed, tainted)
        if tool == "send_email":
            return self._check_email(spec, parsed, tainted, approved)
        return True, ""

    @staticmethod
    def _check_file(spec, a, tainted):
        name = a["name"]
        pat = spec.get("filename_pattern", r"[\w\-. ]+")
        if not re.fullmatch(pat, name) or ".." in name:
            return False, f"file name '{name}' is not allowed"
        sensitive = {s.lower() for s in spec.get("sensitive_files", [])}
        if tainted and name.lower() in sensitive:
            return False, f"'{name}' is sensitive and untrusted content is in the conversation"
        return True, ""

    @staticmethod
    def _check_email(spec, a, tainted, approved):
        m = _EMAIL_RE.match(a["to"].strip())
        if not m:
            return False, "recipient is not a valid email address"
        if len(a["body"]) > spec.get("max_body_chars", 2000):
            return False, "email body is too long"
        if tainted:
            domain = m.group(1).lower()
            trusted = any(domain == d or domain.endswith("." + d) for d in spec.get("trusted_domains", []))
            user_named = a["to"].strip().lower() in {x.lower() for x in approved}
            if not trusted and not user_named:
                return False, f"recipient domain '{domain}' is untrusted and the user did not name this address"
        return True, ""
