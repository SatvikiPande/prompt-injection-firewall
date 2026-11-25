"""
The Firewall: puts the layers together.

  inspect_text(text, source)  -> Decision   (is this text an attack?)
  check_tool_call(name, args) -> Decision   (is this action allowed?)

Flow for text:  normalize -> rules -> ML detector -> take the highest score -> allow/flag/block
Flow for tools: policy.yaml allow-list + argument checks + "tainted" rules
"""
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from .classifier import load_detector
from .logger import EventLog
from .normalize import normalize
from .output_guard import check_output
from .policy import Policy
from .rules import scan

PKG = Path(__file__).resolve().parent


@dataclass
class Decision:
    action: str = "allow"        # allow | flag | block
    score: float = 0.0
    layer: str = "none"          # which layer made the call: rules | detector | policy | output | session | none
    reason: str = ""
    hits: list = field(default_factory=list)
    latency_ms: float = 0.0

    @property
    def blocked(self) -> bool:
        return self.action == "block"


class Firewall:
    def __init__(self, policy=None, detector=None, use_rules=True, use_detector=True, use_policy=True, use_output=True,
                 use_spotlight=True, block_threshold=0.85, flag_threshold=0.5, log=None):
        self.policy, self.detector = policy, detector
        self.use_rules, self.use_detector, self.use_policy, self.use_output = use_rules, use_detector, use_policy, use_output
        self.use_spotlight = use_spotlight
        self.sessions = {}    # session id -> recent scores (to spot repeated probing)
        self.block_threshold, self.flag_threshold = block_threshold, flag_threshold
        self.log = log
        self.latencies = []   # milliseconds per check, used by the evaluation

    # ---- text layer -------------------------------------------------------
    def inspect_text(self, text: str, source: str = "user", session=None) -> Decision:
        t0 = time.perf_counter()
        norm = normalize(text)
        r_score, hits = scan(norm.text, norm.flags, source) if self.use_rules else (0.0, [])
        d_score = self.detector.score(norm.text) if (self.use_detector and self.detector) else 0.0
        score = max(r_score, d_score)

        action = "block" if score >= self.block_threshold else "flag" if score >= self.flag_threshold else "allow"
        layer, reason = "none", ""
        if action != "allow":
            layer = "rules" if r_score >= d_score else "detector"
            reason = f"rules: {', '.join(hits)}" if layer == "rules" else f"detector score {d_score:.2f}"
        # Multi-turn defense: someone probing again and again gets blocked sooner
        if session is not None and (self.use_rules or self.use_detector):
            hist = self.sessions.setdefault(session, [])
            probes = sum(1 for sc in hist[-5:] if sc >= 0.4)
            if probes >= 2 and score >= 0.3 and action != "block":
                action, layer = "block", "session"
                reason = f"repeated suspicious inputs in this session ({probes} recent)"
            hist.append(score)
        dec = Decision(action, round(score, 4), layer, reason, hits, (time.perf_counter() - t0) * 1000)
        self.latencies.append(dec.latency_ms)
        if self.log:
            self.log.add("text", source, dec.action, dec.layer, dec.score, dec.reason, dec.latency_ms, text=text)
        return dec

    # ---- output layer -----------------------------------------------------
    def inspect_output(self, text: str, canaries=()) -> Decision:
        t0 = time.perf_counter()
        if self.use_output:
            cfg = (self.policy.cfg.get("output", {}) if self.policy is not None else {})
            action, reason = check_output(text, canaries, cfg)
        else:
            action, reason = "allow", ""
        dec = Decision(action, 1.0 if action == "block" else 0.0, "output" if action == "block" else "none", reason)
        dec.latency_ms = (time.perf_counter() - t0) * 1000
        self.latencies.append(dec.latency_ms)
        if self.log:
            self.log.add("output", "model", dec.action, dec.layer, dec.score, dec.reason, dec.latency_ms, text=text)
        return dec

    # ---- tool layer -------------------------------------------------------
    def check_tool_call(self, name: str, args: dict, tainted: bool, approved=()) -> Decision:
        t0 = time.perf_counter()
        if self.use_policy and self.policy is not None:
            ok, reason = self.policy.check(name, args, tainted, approved)
            dec = Decision("allow" if ok else "block", 0.0 if ok else 1.0, "none" if ok else "policy", reason)
        else:
            dec = Decision()
        dec.latency_ms = (time.perf_counter() - t0) * 1000
        self.latencies.append(dec.latency_ms)
        if self.log:
            self.log.add("tool", "model", dec.action, dec.layer, dec.score, dec.reason, dec.latency_ms,
                         text=str(args), tool=name)
        return dec

    # ---- spotlighting -----------------------------------------------------
    @staticmethod
    def wrap_untrusted(text: str) -> str:
        """Mark outside content so the model can treat it as data, not as orders."""
        safe = text.replace("UNTRUSTED_DATA", "UNTRUSTED-DATA")
        return f"<<UNTRUSTED_DATA\n{safe}\nUNTRUSTED_DATA>>"


def build_firewall(detector_kind=None, policy_path=None, db_path=None, run_tag="live", log=True, **kw) -> Firewall:
    """Build a Firewall using environment variables for settings (see README)."""
    kw.setdefault("block_threshold", float(os.environ.get("FW_BLOCK_T", 0.85)))
    kw.setdefault("flag_threshold", float(os.environ.get("FW_FLAG_T", 0.5)))
    return Firewall(
        policy=Policy.load(policy_path or os.environ.get("FW_POLICY", PKG / "policy.yaml")),
        detector=load_detector(detector_kind),
        log=EventLog(db_path, run_tag) if log else None,
        **kw,
    )
