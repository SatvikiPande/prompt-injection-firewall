"""
STEP 1 of every check: clean the text.

Attackers hide instructions with tricks: invisible characters, fancy Unicode letters,
HTML comments, base64 blobs. We undo those tricks first, so the next layers see the
"real" text a language model would effectively read.

normalize() returns the cleaned text plus a list of flags describing what we found.
"""
import base64
import binascii
import html
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field

# Characters that are invisible to humans but still present in the text.
_INVISIBLE = dict.fromkeys(
    map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad\u202a\u202b\u202c\u202d\u202e"), None
)
_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
_TAG_RE = re.compile(r"<[^>]+>")


# Lookalike letters (Cyrillic / Greek) that attackers mix into Latin words: "ignоre" with a Cyrillic "о"
_HOMO = {ord(k): v for k, v in {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i"}.items()}
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_SPACED = re.compile(r"(?<!\S)(?:[A-Za-z] ){2,}[A-Za-z](?=\W|$)")
_PCT = re.compile(r"(?:%[0-9A-Fa-f]{2}){3,}")


def _fold_homoglyphs(t: str):
    """Map lookalike letters to Latin, but only inside words that MIX scripts (real Russian/Greek text stays intact)."""
    out, changed = [], False
    for tok in re.split(r"(\s+)", t):
        if re.search(r"[A-Za-z]", tok) and re.search(r"[\u0370-\u03ff\u0400-\u04ff]", tok):
            n = tok.translate(_HOMO)
            changed = changed or n != tok
            tok = n
        out.append(tok)
    return "".join(out), changed


def _fold_leet(t: str):
    """Return (text with leetspeak words fixed, number of words changed). '1gn0re' -> 'ignore'."""
    out, n = [], 0
    for tok in re.split(r"(\s+)", t):
        if (len(tok) >= 4 and re.search(r"[A-Za-z]{2}", tok) and re.search(r"[013457@$]", tok)
                and not re.search(r"[@./:]\w+\.", tok)):
            f = tok.translate(_LEET)
            if f != tok:
                n += 1
            tok = f
        out.append(tok)
    return "".join(out), n


@dataclass
class Normalized:
    text: str
    flags: list = field(default_factory=list)


def _try_base64(token: str):
    """Return the decoded text if `token` is base64 of readable text, else None."""
    try:
        raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
        s = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    if len(s) >= 8 and sum(c.isprintable() or c.isspace() for c in s) / len(s) > 0.95:
        return s
    return None


def normalize(text: str) -> Normalized:
    flags = []
    t = text or ""

    # 1) Fancy/full-width letters -> plain letters (e.g. "ｉｇｎｏｒｅ" -> "ignore")
    n = unicodedata.normalize("NFKC", t)
    if n != t:
        flags.append("unicode_normalized")
    t = n

    # 2) Remove invisible characters ("ig\u200bnore" -> "ignore")
    stripped = t.translate(_INVISIBLE)
    if stripped != t:
        flags.append("zero_width_removed")
    t = stripped

    # 3) Show hidden HTML: keep text inside comments, drop the tags, decode &amp; etc.
    if "<" in t:
        if _COMMENT_RE.search(t):
            flags.append("html_comment_exposed")
            t = _COMMENT_RE.sub(lambda m: " " + m.group(1) + " ", t)
        t = _TAG_RE.sub(" ", t)
    t = html.unescape(t)

    # 3b) Anti-disguise: lookalike letters, spaced-out letters, leetspeak, %-encoding
    t, changed = _fold_homoglyphs(t)
    if changed:
        flags.append("homoglyph_folded")
    extras = []
    if _PCT.search(t):
        dec = urllib.parse.unquote(t)
        if dec != t:
            flags.append("url_decoded")
            extras.append(dec)
    if _SPACED.search(t):
        flags.append("spaced_letters")
        extras.append(_SPACED.sub(lambda m: m.group(0).replace(" ", ""), t))
    leet, n_leet = _fold_leet(t)
    if n_leet >= 2:
        flags.append("leetspeak")
        extras.append(leet)
    if extras:                       # keep the original AND add the cleaned copies, so rules see both
        t = t + " " + " ".join(extras)

    # 4) Decode base64 blobs and append what they say, so later layers can read it
    decoded_parts = []
    for tok in _B64_RE.findall(t):
        s = _try_base64(tok)
        if s:
            decoded_parts.append(s)
    if decoded_parts:
        flags.append("base64_decoded")
        t = t + " " + " ".join(decoded_parts)

    # 5) Tidy whitespace
    t = re.sub(r"[ \t]+", " ", t).strip()
    return Normalized(text=t, flags=flags)
