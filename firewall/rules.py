"""
STEP 2 (Layer 1): fast pattern rules.

Each rule is a regular expression with a weight (how suspicious it is, 0..1).
If several rules match, we combine them like independent evidence ("noisy-or"):
    score = 1 - (1-w1)*(1-w2)*...
So two medium signals together become a strong signal.

scope="untrusted" means the rule only applies to text from files/web pages/tool output.
Example: "send ... to bob@x.com" is normal when the USER writes it, but suspicious
when it appears INSIDE a document the AI is reading.
"""
import re
from dataclasses import dataclass, field

EMAIL = r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"


@dataclass
class Rule:
    name: str
    pattern: str
    weight: float
    scope: str = "any"  # "any" or "untrusted"
    compiled: re.Pattern = field(init=False, repr=False)

    def __post_init__(self):
        self.compiled = re.compile(self.pattern, re.I | re.M)


RULES = [
    Rule("ignore_instructions",
         r"\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|preceding|all|your)\b[^.\n]{0,40}\b(?:instructions?|rules?|prompts?|directions?|guidelines?|restrictions?)\b",
         0.90),
    Rule("role_override",
         r"\b(?:you are now|from now on,? you|pretend (?:to be|you are)|act as (?:if you (?:are|were)|an? (?:unrestricted|jailbroken|uncensored)))\b",
         0.70),
    Rule("developer_mode", r"\b(?:developer mode|dan mode|jailbreak(?:ed)?|do anything now)\b", 0.80),
    Rule("reveal_prompt",
         r"\b(?:reveal|show|print|repeat|display|leak|output)\b[^.\n]{0,30}\b(?:system prompt|hidden prompt|initial prompt|your instructions|your prompt)\b",
         0.85),
    Rule("fake_system_tag",
         r"(?:^|\n)\s*(?:\[(?:system|assistant|developer)\]|(?:system|assistant|developer)\s*:|<\|?(?:im_start|system|endoftext)\|?>|#{2,}\s*(?:system|instructions?)\b)",
         0.60),
    Rule("hide_from_user",
         r"\b(?:do not|don't|never)\b[^.\n]{0,30}\b(?:tell|inform|mention|reveal|notify)\b[^.\n]{0,20}\b(?:user|human|anyone)\b",
         0.80),
    Rule("message_to_ai",
         r"\b(?:important|urgent|attention|note)\b[^.\n]{0,25}\b(?:for|to)\b[^.\n]{0,15}\b(?:ai|assistant|model|llm|agent)\b",
         0.70, scope="untrusted"),
    Rule("exfiltrate_email",
         r"\b(?:send|forward|email|e-mail|mail|transmit|upload|post)\b[^\n]{0,80}" + EMAIL,
         0.80, scope="untrusted"),
    Rule("exfiltrate_url",
         r"\b(?:append|include|add|embed|render|insert|attach|end with)\b[^\n]{0,80}https?://[^\s)]+[?&]\w+=",
         0.75, scope="untrusted"),
    Rule("tool_command",
         r"\b(?:call|use|invoke|run|execute)\b[^.\n]{0,25}\b(?:send_email|read_file|read_webpage)\b",
         0.70, scope="untrusted"),
    Rule("sensitive_target",
         r"\b(?:secrets?\.txt|passwords?|api[_ -]?keys?|credentials?|private key|\.env)\b",
         0.30, scope="untrusted"),
    # Hindi / Hinglish examples (extend these with your own!)
    Rule("hindi_ignore",
         r"(?:पिछले|पुराने|सभी|ऊपर के)[^\n.]{0,20}(?:निर्देश|आदेश)[^\n.]{0,20}(?:अनदेखा|नजरअंदाज|नज़रअंदाज़|भूल)",
         0.90),
    Rule("hinglish_ignore",
         r"\b(?:pichle|purane|sabhi|upar ke)\b[^\n.]{0,20}\b(?:instructions?|nirdesh|aadesh|rules?)\b[^\n.]{0,20}\b(?:ignore|bhool|nazarandaz)",
         0.90),
]

# Small extra signals coming from the normalizer
FLAG_WEIGHTS = {"zero_width_removed": 0.35, "base64_decoded": 0.20, "homoglyph_folded": 0.40,
                "spaced_letters": 0.35, "leetspeak": 0.30, "url_decoded": 0.20}


def scan(text: str, flags=(), source: str = "user"):
    """Return (score 0..1, list of rule names that matched)."""
    hits, weights = [], []
    for r in RULES:
        if r.scope == "untrusted" and source != "untrusted":
            continue
        if r.compiled.search(text):
            hits.append(r.name)
            weights.append(r.weight)
    for f in flags:
        if f in FLAG_WEIGHTS:
            hits.append(f)
            weights.append(FLAG_WEIGHTS[f])
    miss = 1.0
    for w in weights:
        miss *= 1 - w
    return round(1 - miss, 4), hits
