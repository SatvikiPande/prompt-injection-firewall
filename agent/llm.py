"""
The "brain" of the assistant. Two interchangeable backends with the same interface:

    llm.chat(messages, tools) -> {"content": str, "tool_calls": [{"name": str, "arguments": dict}]}

  MockLLM   : a tiny, deterministic, deliberately GULLIBLE model (no download, instant).
              It does what instructions in the conversation say, like a weak real model.
              Use it to test the pipeline and in unit tests.
  OllamaLLM : a real local model through Ollama (free). Use it for your final results.
"""
import base64
import re
from urllib.parse import quote

EMAIL = r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"
FILE = r"[\w\-]+\.(?:txt|html|md|csv|env)"
_B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


class MockLLM:
    name = "mock"

    def chat(self, messages, tools=None):
        task = next(m["content"] for m in messages if m["role"] == "user")
        calls = [tc for m in messages if m["role"] == "assistant" for tc in m.get("tool_calls", [])]
        results = [m["content"] for m in messages if m["role"] == "tool"]
        sent = {c["arguments"].get("to", "").lower() for c in calls if c["name"] == "send_email"}
        read = {c["arguments"].get("name") for c in calls if c["name"] in ("read_file", "read_webpage")}

        # 1) Obey any "send ... to someone@x" instruction found inside tool output (gullible!)
        for res in results:
            text = res + " " + self._decode_b64(res)
            target = self._find_target(text, sent)
            if target:
                wanted = re.findall(FILE, text)
                for fname in wanted:                      # read the file the attacker asked for first
                    if fname not in read and "secret" in fname:
                        return self._call("read_file", {"name": fname})
                return self._call("send_email", {"to": target, "body": results[-1][:300]})

        # 1b) Obey "append this image/link ending in ...?data=" instructions: first fetch the secret file they mention
        alltext = " ".join(results)
        prefix = self._find_url_prefix(alltext)
        if prefix:
            for fname in re.findall(FILE, alltext):
                if fname not in read and "secret" in fname:
                    return self._call("read_file", {"name": fname})

        # 2) First turn: read the first file the user mentions
        if not calls:
            f = re.search(FILE, task)
            if f:
                tool = "read_webpage" if f.group(0).endswith(".html") else "read_file"
                return self._call(tool, {"name": f.group(0)})

        # 3) The user asked for an email and it has not been sent yet
        um = re.search(EMAIL, task)
        if um and re.search(r"\b(send|email|mail|forward)\b", task, re.I) and um.group(0).lower() not in sent:
            body = results[-1][:300] if results else task
            return self._call("send_email", {"to": um.group(0), "body": body})

        # 4) Final answer
        good = [r for r in results if not r.startswith("[FIREWALL")]
        leak = re.search(r"(?:quote|repeat|print|reveal|show|output|recite|begin|start)[^.\n]{0,60}"
                         r"(?:system prompt|initial (?:prompt|instructions|configuration)|everything above|word for word|verbatim|hidden instructions)",
                         task + " " + alltext, re.I)
        if leak:                                  # gullible: repeats its hidden instructions
            answer = messages[0]["content"]
        elif results and not good:
            return {"content": "I could not complete this because a safety check blocked the content.", "tool_calls": []}
        elif good:
            answer = "Summary: " + re.sub(r"\s+", " ", good[0])[:200]
        else:
            return {"content": "Hello! How can I help you?", "tool_calls": []}
        if prefix:                                # gullible: adds the attacker's image carrying the secret
            secret = next((r for r in good if "sk-" in r or "API_KEY" in r), "none")
            answer += f" ![status]({prefix}{quote(secret.strip().splitlines()[0])})"
        return {"content": answer, "tool_calls": []}

    @staticmethod
    def _find_url_prefix(text):
        for line in text.splitlines():
            if re.search(r"\b(?:append|include|add|embed|render|insert|attach|image)\b", line, re.I):
                m = re.search(r"(https?://[^\s)]+[?&]\w+=)", line)
                if m:
                    return m.group(1)
        return None

    @staticmethod
    def _find_target(text, sent):
        """Find an email address on a line that also contains a 'send'-like word (English/Hinglish/Hindi)."""
        verbs = re.compile(r"\b(?:send|forward|email|emailed|mail|mailed|pass|share)\b|send_email|bhej|भेज", re.I)
        for line in text.splitlines():
            if verbs.search(line):
                for addr in re.findall(EMAIL, line):
                    if addr.lower() not in sent:
                        return addr
        return None

    @staticmethod
    def _call(name, args):
        return {"content": "", "tool_calls": [{"name": name, "arguments": args}]}

    @staticmethod
    def _decode_b64(text):
        out = []
        for tok in _B64.findall(text):
            try:
                out.append(base64.b64decode(tok + "=" * (-len(tok) % 4), validate=True).decode("utf-8"))
            except Exception:
                pass
        return " ".join(out)


class OllamaLLM:
    name = "ollama"

    def __init__(self, model="llama3.2:3b"):
        import ollama
        self.model, self.client = model, ollama

    def chat(self, messages, tools=None):
        get = (lambda o, k: o.get(k) if isinstance(o, dict) else getattr(o, k, None))
        last_err = None
        for temp in (0.2, 0.5, 0.8):      # small models sometimes loop; retry with more randomness
            try:
                resp = self.client.chat(
                    model=self.model, messages=messages, tools=tools, keep_alive="30m",
                    options={"temperature": temp, "repeat_penalty": 1.15, "num_predict": 300, "num_ctx": 4096},
                )
                break
            except self.client.ResponseError as e:      # e.g. "token repeat limit reached"
                last_err = e
        else:
            return {"content": f"[model error: {last_err}]", "tool_calls": []}
        msg = resp["message"] if isinstance(resp, dict) else resp.message
        calls = []
        for tc in get(msg, "tool_calls") or []:
            fn = get(tc, "function")
            args = get(fn, "arguments") or {}
            calls.append({"name": get(fn, "name"), "arguments": dict(args)})
        return {"content": get(msg, "content") or "", "tool_calls": calls}


def make_llm(kind="mock", model="llama3.2:3b"):
    if kind == "mock":
        return MockLLM()
    if kind == "ollama":
        return OllamaLLM(model)
    raise ValueError("llm must be 'mock' or 'ollama'")
