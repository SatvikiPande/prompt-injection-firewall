"""
STEP 3 (Layer 2): the machine-learning detector.

It reads a text and returns a number from 0 (looks normal) to 1 (looks like an injection).
Two interchangeable backends:

  tfidf : tiny scikit-learn model (words + character patterns -> logistic regression).
          Trains in about a second on a laptop CPU, no downloads. Used by default.
  hf    : a pretrained transformer from Hugging Face (DeBERTa). Stronger, but needs
          `pip install transformers torch` and a one-time model download.

Choose with the environment variable FW_DETECTOR=tfidf|hf|none.

Long documents are cut into overlapping chunks and we keep the highest score, so an
attack buried in the middle of a long page is not "diluted" by the harmless text around it.
"""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _chunks(text: str, words: int = 80, stride: int = 40):
    w = text.split()
    if len(w) <= words:
        return [text]
    out, i = [], 0
    while True:
        out.append(" ".join(w[i:i + words]))
        if i + words >= len(w):
            break
        i += stride
    return out


def build_pipeline():
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import FeatureUnion, Pipeline

    feats = FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, lowercase=True)),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True, lowercase=True, min_df=2)),
    ])
    return Pipeline([("features", feats), ("model", LogisticRegression(C=10, max_iter=2000, class_weight="balanced"))])


def train_tfidf(csv_paths, out_path):
    """Train on one or more CSV files with columns: text,label (1 = injection, 0 = normal)."""
    import joblib
    import pandas as pd

    df = pd.concat([pd.read_csv(p)[["text", "label"]] for p in csv_paths]).dropna()
    df["label"] = df["label"].astype(int)
    pipe = build_pipeline().fit(df["text"].astype(str), df["label"])
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipe, out_path)
    return len(df)


class TfidfDetector:
    name = "tfidf"

    def __init__(self, model_path=None):
        import joblib

        path = Path(model_path or os.environ.get("FW_TFIDF_MODEL", ROOT / "models" / "tfidf.joblib"))
        if not path.exists():  # first run: train automatically from the bundled data
            data = [ROOT / "data" / "seed_train.csv"]
            extra = ROOT / "data" / "deepset_train.csv"
            if extra.exists():
                data.append(extra)
            train_tfidf(data, path)
        self.pipe = joblib.load(path)
        self.pos = list(self.pipe.classes_).index(1)

    def score(self, text: str) -> float:
        probs = self.pipe.predict_proba(_chunks(text))[:, self.pos]
        return float(probs.max())


class HFDetector:
    name = "hf"

    def __init__(self, model=None):
        from transformers import pipeline  # imported late: heavy

        self.model = model or os.environ.get("FW_HF_MODEL", "protectai/deberta-v3-base-prompt-injection-v2")
        self.pipe = pipeline("text-classification", model=self.model, truncation=True, max_length=512)

    def score(self, text: str) -> float:
        best = 0.0
        for out in self.pipe(_chunks(text, words=200, stride=100)):
            label, s = str(out["label"]).upper(), float(out["score"])
            p = s if ("INJECTION" in label or label in {"LABEL_1", "1"}) else 1.0 - s
            best = max(best, p)
        return best


def load_detector(kind=None):
    kind = (kind or os.environ.get("FW_DETECTOR", "tfidf")).lower()
    if kind == "none":
        return None
    if kind == "tfidf":
        return TfidfDetector()
    if kind == "hf":
        return HFDetector()
    raise ValueError(f"unknown detector '{kind}' (use tfidf, hf or none)")
