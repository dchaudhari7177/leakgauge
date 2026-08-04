"""Render the leakgauge hero figure from the committed results JSONs.

Reads every ``results/<provider>_<model>.json`` produced by the benchmark and
draws hijack ASR next to verified-leakage ASR for each model, with the
bootstrap confidence intervals stored in each file. Every number on the plot
comes straight from those JSONs; nothing is hand-entered.

Run:
    uv run python scripts/plot_pilot.py
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402  (backend must be set before pyplot)

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
OUT = ROOT / "assets" / "leakgauge_pilot.png"

# Short display names, keyed by the "model" field in each JSON.
DISPLAY = {
    "openai:gpt-4o": "gpt-4o",
    "openai:gpt-4o-mini": "gpt-4o-mini",
    "openrouter:meta-llama/llama-3.3-70b-instruct": "llama-3.3-70b",
}


def load_runs() -> list[dict]:
    runs = []
    for path in sorted(RESULTS.glob("*.json")):
        with path.open() as fh:
            runs.append(json.load(fh))
    if not runs:
        raise SystemExit(f"no result JSONs found in {RESULTS}")
    # Sort by leakage ASR so the story reads left to right.
    runs.sort(key=lambda r: r["aggregate"]["leakage_asr"]["point"])
    return runs


def err(metric: dict) -> tuple[float, float]:
    """Asymmetric (lower, upper) error-bar lengths from a point/lo/hi block."""
    point = metric["point"]
    return point - metric["lo"], metric["hi"] - point


def main() -> None:
    runs = load_runs()
    labels = [DISPLAY.get(r["model"], r["model"]) for r in runs]
    hijack = [r["aggregate"]["hijack_asr"]["point"] * 100 for r in runs]
    leak = [r["aggregate"]["leakage_asr"]["point"] * 100 for r in runs]

    def err_bars(key: str) -> list[list[float]]:
        pairs = (err(r["aggregate"][key]) for r in runs)
        return [[e * 100 for e in side] for side in zip(*pairs, strict=True)]

    hijack_err = err_bars("hijack_asr")
    leak_err = err_bars("leakage_asr")

    n_cases = runs[0]["n_cases"]
    k = runs[0]["k"]

    x = range(len(runs))
    width = 0.38
    fig, ax = plt.subplots(figsize=(16, 9), dpi=100)
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")

    ax.bar(
        [i - width / 2 for i in x],
        hijack,
        width,
        yerr=hijack_err,
        capsize=6,
        color="#9aa7b1",
        label="Task hijack (agent went off-task)",
    )
    ax.bar(
        [i + width / 2 for i in x],
        leak,
        width,
        yerr=leak_err,
        capsize=6,
        color="#c0392b",
        label="Verified leakage (secret actually left)",
    )

    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, fontsize=15)
    ax.set_ylabel("Attack success rate (%)", fontsize=15)
    ax.set_title(
        f"leakgauge: getting hijacked is not the same as leaking\n"
        f"{n_cases} cases x {k} seeds per model, bars show 95% bootstrap CI",
        fontsize=18,
        pad=16,
    )
    ax.legend(fontsize=13, frameon=False, loc="upper left")
    ax.spines[["top", "right"]].set_visible(False)
    ax.tick_params(labelsize=13)
    ax.margins(y=0.15)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(OUT, facecolor="white")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
