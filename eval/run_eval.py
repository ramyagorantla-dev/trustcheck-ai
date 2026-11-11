"""Evaluate TrustCheck against baselines.

Systems compared on the same test set:
  classic   TF-IDF + logistic regression (5-fold cross-validation), classic ML baseline
  rules     all tools, no LLM
  llm_only  local LLM, no tools
  agent     full TrustCheck agent (LLM + tools + guardrail)

Usage:
  python eval/run_eval.py                         # rules + classic only (no Ollama needed)
  python eval/run_eval.py --llm                   # + llm_only and agent with default model
  python eval/run_eval.py --llm --models qwen2.5:3b qwen2.5:7b   # compare model sizes
  python eval/run_eval.py --llm --provider groq --models openai/gpt-oss-20b openai/gpt-oss-120b

Outputs go to results/: metrics.csv, predictions.csv, failures.md, confusion_matrices.png
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from trustcheck.agent import TrustCheckAgent, llm_only, rules_only  # noqa: E402
from trustcheck.llm import make_client  # noqa: E402

RESULTS = ROOT / "results"


def load(path):
    return [json.loads(l) for l in Path(path).read_text(encoding="utf-8").splitlines() if l.strip()]


def classic_baseline(items):
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import StratifiedKFold, cross_val_predict
    from sklearn.pipeline import make_pipeline
    X = [it["text"] for it in items]
    y = [1 if it["label"] == "scam" else 0 for it in items]
    pipe = make_pipeline(TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=1),
                         LogisticRegression(max_iter=2000, class_weight="balanced"))
    t0 = time.time()
    probs = cross_val_predict(pipe, X, y, cv=StratifiedKFold(5, shuffle=True, random_state=42),
                              method="predict_proba")[:, 1]
    per = (time.time() - t0) / len(items)
    return [{"id": it["id"], "system": "classic_tfidf_lr", "pred_scam": bool(p >= 0.5),
             "risk_score": int(p * 100), "latency_s": per, "tools_used": "", "scam_type": "",
             "evidence": ""} for it, p in zip(items, probs)]


def run_system(name, fn, items):
    rows = []
    for i, it in enumerate(items, 1):
        try:
            r = fn(it["text"], it["input_type"])
            rows.append({"id": it["id"], "system": name, "pred_scam": r.is_scam, "risk_score": r.risk_score,
                         "latency_s": r.latency_s, "tools_used": ",".join(r.tools_used),
                         "scam_type": r.scam_type, "evidence": " | ".join(r.evidence[:4]),
                         "error": r.error})
        except Exception as e:
            rows.append({"id": it["id"], "system": name, "pred_scam": None, "risk_score": None,
                         "latency_s": None, "tools_used": "", "scam_type": "", "evidence": "", "error": str(e)})
        print(f"\r  {name}: {i}/{len(items)}", end="", flush=True)
    print()
    return rows


def metrics(df):
    out = []
    for system, g in df.groupby("system", sort=False):
        g = g.dropna(subset=["pred_scam"])
        y, p = g["label"] == "scam", g["pred_scam"].astype(bool)
        tp, fp = int((y & p).sum()), int((~y & p).sum())
        fn, tn = int((y & ~p).sum()), int((~y & ~p).sum())
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        row = {"system": system, "n": len(g), "accuracy": (tp + tn) / len(g), "precision": prec,
               "recall": rec, "f1": f1, "false_negative_rate": fn / (tp + fn) if tp + fn else 0,
               "false_positive_rate": fp / (fp + tn) if fp + tn else 0,
               "mean_latency_s": g["latency_s"].mean(), "tp": tp, "fp": fp, "fn": fn, "tn": tn}
        for t, gt in g.groupby("input_type"):
            row[f"acc_{t}"] = ((gt["label"] == "scam") == gt["pred_scam"].astype(bool)).mean()
        out.append(row)
    return pd.DataFrame(out)


def failures_md(df):
    lines = ["# Failure analysis\n", "Every misclassified example, per system. "
             "FN = scam marked safe (the dangerous error); FP = genuine message flagged.\n"]
    for system, g in df.groupby("system", sort=False):
        bad = g[(g["label"] == "scam") != g["pred_scam"].astype(bool)]
        lines.append(f"\n## {system}: {len(bad)} errors\n")
        for _, r in bad.iterrows():
            kind = "FN (missed scam)" if r["label"] == "scam" else "FP (false alarm)"
            lines.append(f"### {r['id']} · {r['input_type']} · {r['category']} · {kind} · score {r['risk_score']}")
            lines.append("```\n" + r["text"][:600] + "\n```")
            if r.get("evidence"):
                lines.append(f"Evidence given: {r['evidence']}")
            lines.append("Why it failed (fill in): \n")
    return "\n".join(lines)


def plot_confusions(m):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    n = len(m)
    fig, axes = plt.subplots(1, n, figsize=(3.2 * n, 3.2))
    axes = [axes] if n == 1 else axes
    for ax, (_, r) in zip(axes, m.iterrows()):
        mat = [[r.tn, r.fp], [r.fn, r.tp]]
        ax.imshow(mat, cmap="Blues")
        for i in range(2):
            for j in range(2):
                ax.text(j, i, mat[i][j], ha="center", va="center", fontsize=14)
        ax.set_xticks([0, 1], ["pred legit", "pred scam"])
        ax.set_yticks([0, 1], ["legit", "scam"])
        ax.set_title(f"{r.system}\nF1={r.f1:.2f}", fontsize=10)
    fig.tight_layout()
    fig.savefig(RESULTS / "confusion_matrices.png", dpi=150)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(ROOT / "data/eval/testset.jsonl"))
    ap.add_argument("--llm", action="store_true", help="also run llm_only and agent (needs Ollama)")
    ap.add_argument("--models", nargs="*", default=None, help="Ollama models to compare")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--provider", default=None, help="ollama (default) or groq")
    args = ap.parse_args()

    items = load(args.data)[: args.limit]
    RESULTS.mkdir(exist_ok=True)
    print(f"Evaluating on {len(items)} items")

    rows = classic_baseline(items)
    rows += run_system("rules_only", lambda t, it: rules_only(t, it), items)

    if args.llm:
        for model in (args.models or [None]):
            client = make_client(model=model, provider=args.provider)
            if not client.is_available():
                print(f"!! Model '{client.model}' not available, skipping. "
                      f"(Ollama: run `ollama pull {client.model}`. Groq: put GROQ_API_KEY in .env)")
                continue
            tag = client.model
            rows += run_system(f"llm_only[{tag}]", lambda t, it, c=client: llm_only(t, c, it), items)
            agent = TrustCheckAgent(client=client)
            rows += run_system(f"agent[{tag}]", lambda t, it, a=agent: a.analyze(t, it), items)

    meta = pd.DataFrame(items)[["id", "label", "input_type", "category", "text"]]
    df = pd.DataFrame(rows).merge(meta, on="id")
    df.to_csv(RESULTS / "predictions.csv", index=False)
    m = metrics(df)
    m.to_csv(RESULTS / "metrics.csv", index=False)
    (RESULTS / "failures.md").write_text(failures_md(df), encoding="utf-8")
    try:
        plot_confusions(m)
    except Exception as e:
        print("plot skipped:", e)
    with pd.option_context("display.width", 200, "display.max_columns", 30, "display.float_format", "{:.2f}".format):
        print(m.drop(columns=["tp", "fp", "fn", "tn"]))
    print(f"\nSaved to {RESULTS}/")


if __name__ == "__main__":
    main()
