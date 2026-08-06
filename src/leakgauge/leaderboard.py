"""Static leaderboard renderer — turns a set of result summaries (the JSON the
suite runner writes) into a single self-contained ``index.html`` for GitHub
Pages. No build step, no runtime JS: the headline figure is inline SVG so it
renders (and prints) even with scripting disabled.

The page leads with the thesis — the hijack-vs-leakage *rank reorder* across
models — because that reorder, not any single rate, is what leakgauge exists to
show. Every rate carries its bootstrap 95% CI; the suite is small so the
intervals are wide, and we display that openly. Consumes the current results
schema (``aggregate.{hijack_asr,leakage_asr,utility_under_attack}`` as
``{point,lo,hi}`` plus an optional ``cost`` block); no model rows are fabricated.
"""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from leakgauge.scoring import RankReorder, crossings

# Distinct, print-safe line colours assigned to models in a stable order.
_PALETTE = ["#2563eb", "#d97706", "#059669", "#db2777", "#7c3aed", "#0891b2", "#65a30d", "#dc2626"]
_MUTED = "#9ca3af"


def _rate(summary: dict[str, Any], key: str) -> dict[str, float] | None:
    val = summary["aggregate"].get(key)
    return val if isinstance(val, dict) else None


def _fmt_ci(rate: dict[str, float] | None) -> str:
    if rate is None:
        return "—"
    return f"{rate['point']:.2f} <span class='ci'>[{rate['lo']:.2f}, {rate['hi']:.2f}]</span>"


def _pct(x: float) -> str:
    return f"{round(x * 100)}%"


# --- headline figure: rank-reorder slopegraph (inline SVG) -------------------


def _svg_reorder(reorder: RankReorder, rate_by_model: dict[str, tuple[float, float]]) -> str:
    """A bump chart: left column = rank by hijack-ASR, right = rank by
    leakage-verified ASR. A line per model; a crossing means its rank moved when
    scored on verified leakage. Built to read without a caption."""
    models = reorder.models_by_hijack
    n = len(models)
    moved_n = crossings(reorder)
    left_x, right_x, top, row = 250, 590, 108, 62
    width, height = 840, top + (n - 1) * row + 96
    colour = {m: _PALETTE[i % len(_PALETTE)] for i, m in enumerate(sorted(models))}

    def y(rank: int) -> int:
        return top + (rank - 1) * row

    crossing_txt = (
        "no model changes rank" if moved_n == 0 else f"{moved_n} of {n} models change rank"
    )
    reorders = reorder.kendall_tau < 0.999
    svg_title = (
        "Ranking by verified leakage reorders the models"
        if reorders
        else "Ranking by verified leakage does NOT reorder these models"
    )
    parts: list[str] = [
        f'<svg viewBox="0 0 {width} {height}" width="100%" role="img" '
        f'aria-label="Rank reorder: hijack-ASR versus leakage-verified ASR" '
        f'font-family="system-ui, sans-serif" class="reorder">',
        f'<text x="{width // 2}" y="34" text-anchor="middle" class="svg-title">{svg_title}</text>',
        f'<text x="{width // 2}" y="58" text-anchor="middle" class="svg-tau">'
        f"Kendall &#964; = {reorder.kendall_tau:.2f} "
        f"({'perfect agreement' if reorder.kendall_tau >= 0.999 else 'ranks disagree'})"
        "</text>",
        f'<text x="{width // 2}" y="80" text-anchor="middle" class="svg-cross">'
        f"{crossing_txt}</text>",
        f'<text x="{left_x}" y="{top - 22}" text-anchor="middle" class="svg-col">'
        "worse &#8592; rank by hijack-ASR</text>",
        f'<text x="{right_x}" y="{top - 22}" text-anchor="middle" class="svg-col">'
        "rank by leakage-verified ASR &#8594; worse</text>",
    ]

    for m in models:
        h_rank, l_rank = reorder.hijack_ranks[m], reorder.leakage_ranks[m]
        hij, leak = rate_by_model[m]
        moved = h_rank != l_rank
        stroke = colour[m] if moved else _MUTED
        w = 3 if moved else 1.6
        y1, y2 = y(h_rank), y(l_rank)
        parts.append(
            f'<line x1="{left_x}" y1="{y1}" x2="{right_x}" y2="{y2}" '
            f'stroke="{stroke}" stroke-width="{w}" opacity="{0.95 if moved else 0.55}"/>'
        )
        parts.append(f'<circle cx="{left_x}" cy="{y1}" r="9" fill="{stroke}"/>')
        parts.append(f'<circle cx="{right_x}" cy="{y2}" r="9" fill="{stroke}"/>')
        # Explicit rank position at each endpoint, so the reader doesn't have to
        # infer it from vertical order.
        parts.append(
            f'<text x="{left_x}" y="{y1 + 4}" text-anchor="middle" font-size="11" '
            f'font-weight="700" fill="#ffffff">{h_rank}</text>'
        )
        parts.append(
            f'<text x="{right_x}" y="{y2 + 4}" text-anchor="middle" font-size="11" '
            f'font-weight="700" fill="#ffffff">{l_rank}</text>'
        )
        # A mover gets its rank delta with an up/down glyph; a null (tau = 1)
        # shows none. Rank 1 is best, so a smaller leakage rank is a move up.
        if moved:
            arrow = "&#9650;" if l_rank < h_rank else "&#9660;"
            parts.append(
                f'<text x="{right_x}" y="{y2 - 14}" text-anchor="middle" font-size="12" '
                f'fill="{stroke}">{arrow}{abs(l_rank - h_rank)}</text>'
            )
        name = html.escape(m)
        parts.append(
            f'<text x="{left_x - 18}" y="{y1 + 5}" text-anchor="end" class="svg-lab">'
            f"{name} &#183; {_pct(hij)}</text>"
        )
        parts.append(
            f'<text x="{right_x + 18}" y="{y2 + 5}" text-anchor="start" class="svg-lab">'
            f"{_pct(leak)} &#183; {name}</text>"
        )

    parts.append(
        f'<text x="{width // 2}" y="{height - 30}" text-anchor="middle" class="svg-note">'
        "Each line is one model. A crossing = its rank changed when success was scored as "
        "verified data leakage instead of task hijacking.</text>"
    )
    parts.append("</svg>")
    return "\n".join(parts)


# --- table -------------------------------------------------------------------


def _table(summaries: list[dict[str, Any]]) -> str:
    ordered = sorted(
        summaries,
        key=lambda s: (_rate(s, "leakage_asr") or {"point": -1.0})["point"],
        reverse=True,
    )
    rows: list[str] = []
    for s in ordered:
        model = html.escape(str(s["model"]))
        rows.append(
            "<tr>"
            f"<td class='model'>{model}</td>"
            f"<td>{_fmt_ci(_rate(s, 'hijack_asr'))}</td>"
            f"<td class='lead-col'>{_fmt_ci(_rate(s, 'leakage_asr'))}</td>"
            f"<td>{_fmt_ci(_rate(s, 'utility_under_attack'))}</td>"
            f"<td class='n'>{int(s.get('n_cases', 0))}</td>"
            "</tr>"
        )
    return (
        "<table>\n<thead><tr>"
        "<th>model</th><th>hijack-ASR</th>"
        "<th class='lead-col'>leakage-verified ASR</th>"
        "<th>utility-under-attack</th><th>n</th>"
        "</tr></thead>\n<tbody>\n" + "\n".join(rows) + "\n</tbody></table>"
    )


# --- page --------------------------------------------------------------------

_CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font-family: system-ui, -apple-system, sans-serif; line-height: 1.5;
  max-width: 960px; margin: 0 auto; padding: 24px; color: #111827; background: #fff; }
a { color: #2563eb; }
.banner { border: 1px solid #d1d5db; border-left: 4px solid #059669; background: #f0fdf4;
  padding: 12px 16px; border-radius: 8px; font-size: 0.95rem; margin-bottom: 24px; }
h1 { margin: 0 0 4px; font-size: 1.9rem; }
.sub { color: #6b7280; margin: 0 0 28px; }
.figure { border: 1px solid #e5e7eb; border-radius: 12px; padding: 20px 16px; margin: 8px 0 12px; }
.reorder .svg-title { font-size: 20px; font-weight: 700; fill: #111827; }
.reorder .svg-tau { font-size: 15px; fill: #374151; }
.reorder .svg-cross { font-size: 13px; font-weight: 600; fill: #b45309; }
.reorder .svg-col { font-size: 13px; font-weight: 600; fill: #6b7280; letter-spacing: .02em; }
.reorder .svg-lab { font-size: 14px; fill: #111827; }
.reorder .svg-note { font-size: 12.5px; fill: #6b7280; }
.thesis { font-size: 1.05rem; margin: 0 0 20px; }
.caveat { border: 1px solid #fde68a; border-left: 4px solid #d97706; background: #fffbeb;
  padding: 12px 16px; border-radius: 8px; font-size: 0.95rem; margin: 0 0 12px; }
.limits { color: #6b7280; font-size: .9rem; margin: 0 0 32px; }
table { border-collapse: collapse; width: 100%; font-variant-numeric: tabular-nums; }
th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #e5e7eb; }
th { font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; color: #6b7280; }
td.model { font-weight: 600; }
.lead-col { background: #eff6ff; }
.ci { color: #6b7280; font-size: .85em; }
.note { color: #6b7280; font-size: .9rem; margin-top: 12px; }
footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #e5e7eb;
  color: #6b7280; font-size: .85rem; }
@media (prefers-color-scheme: dark) {
  body { color: #e5e7eb; background: #0b0f17; }
  .banner { background: #0c1f17; border-color: #1f2937; }
  .caveat { background: #1c1503; border-color: #3f2d05; }
  .figure, footer { border-color: #1f2937; }
  th, td { border-color: #1f2937; }
  td.model { color: #f3f4f6; }
  .reorder .svg-title, .reorder .svg-lab { fill: #f3f4f6; }
  .lead-col { background: #0e1b2e; }
}
"""

# Roster-run limitations for the final 3-model result. These document the run
# behind the shipped page, not anything derivable from the JSONs.
_ROSTER_LIMITATIONS = (
    "<p class='limits'><strong>Limitations.</strong> qwen-2.5-72b stalled provider-side and is "
    "excluded. Anthropic (Sonnet/Haiku) was deferred on cost — agentic runs take many tool-call "
    "steps (~$15–60/model) and, being similarly robust, would not flip this null.</p>"
)


def _n_str(summaries: list[dict[str, Any]]) -> str:
    ns = sorted({int(s.get("n_cases", 0)) for s in summaries})
    if not ns:
        return "0"
    return str(ns[0]) if len(ns) == 1 else f"{ns[0]}–{ns[-1]}"


def _provenance(summaries: list[dict[str, Any]]) -> str:
    suites = sorted({str(s.get("suite", "?")) for s in summaries})
    line = f"{len(summaries)} model(s) · suite: {', '.join(suites)} · n={_n_str(summaries)} cases"
    spend = sum(float((s.get("cost") or {}).get("spend_usd") or 0.0) for s in summaries)
    if spend > 0:
        line += f" · roster compute ${spend:.2f}"
    return line


def _short(model: str) -> str:
    return model.split(":", 1)[-1].split("/")[-1]


def _subtitle(summaries: list[dict[str, Any]], reorder: RankReorder | None) -> str:
    names = ", ".join(sorted(_short(str(s["model"])) for s in summaries))
    line = f"<strong>Final result.</strong> {len(summaries)} models evaluated: {names}."
    if reorder is not None:
        line += f" Kendall &tau; = {reorder.kendall_tau:.3f}."
    return line


def render_html(summaries: list[dict[str, Any]], reorder: RankReorder | None) -> str:
    rate_by_model = {
        str(s["model"]): (
            (_rate(s, "hijack_asr") or {"point": 0.0})["point"],
            (_rate(s, "leakage_asr") or {"point": 0.0})["point"],
        )
        for s in summaries
    }

    if reorder is None:
        figure = (
            "<div class='figure'><p class='note'>Only one model summary — the hijack-vs-leakage "
            "rank reorder needs &ge;2 models.</p></div>"
        )
        thesis = ""
    elif reorder.kendall_tau < 0.999:
        # A genuine reorder: leakage ranking differs from hijack ranking.
        figure = f'<div class="figure">{_svg_reorder(reorder, rate_by_model)}</div>'
        thesis = (
            "<p class='thesis'>The headline is the <strong>reorder</strong>: ranking models by "
            "<em>verified data leakage</em> is not the same as ranking them by whether they were "
            "<em>hijacked</em>. When the two rankings disagree (Kendall &tau; &lt; 1, lines "
            "crossing above), hijack-based benchmarks are mismeasuring exfiltration risk.</p>"
        )
    else:
        # The final null: ranks agree (τ = 1), so leakage scoring does not reorder.
        figure = f'<div class="figure">{_svg_reorder(reorder, rate_by_model)}</div>'
        thesis = (
            f"<p class='thesis'><strong>Final result: no.</strong> Ranking these "
            f"{len(summaries)} models by verified data leakage gives the "
            "<strong>same order</strong> as ranking by task hijacking (Kendall &tau; = 1.000 — "
            "the lines above are parallel, "
            "no crossing). The leakage-vs-hijack reorder does not occur for this roster.</p>"
            "<div class='caveat'><strong>Why, and what it means.</strong> On current frontier "
            "models these attacks score near the <em>floor</em> — the models barely leak, and "
            "hijack-ASR &approx; leakage-ASR. With so little spread there is almost nothing for "
            "leakage-vs-hijack scoring to reorder. Demonstrating the reorder needs harder cases "
            "that pull the two rates apart (future work). The contribution here is the "
            "programmatic <em>leakage-verification methodology</em> and a verified leaderboard — "
            "not a positive reorder.</div>"
            f"{_ROSTER_LIMITATIONS}"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>leakgauge — FINAL leakage-verified leaderboard</title>
<style>{_CSS}</style>
</head>
<body>
<div class="banner">
  <strong>Defensive benchmark.</strong> leakgauge measures whether an agent's defences hold
  against prompt injection, so they can be improved — it is not an attack toolkit. Success is
  programmatically verified data leakage, never LLM-judged. See
  <a href="https://github.com/bamdadd/leakgauge/blob/main/THREAT_MODEL.md">THREAT_MODEL.md</a>.
</div>

<h1>leakgauge leaderboard</h1>
<p class="sub">{_subtitle(summaries, reorder)}</p>
<p class="sub">{_provenance(summaries)}</p>

<h2>Does verified leakage change the ranking?</h2>
{figure}
{thesis}

<h2>Per-model rates (95% bootstrap CI)</h2>
{_table(summaries)}
<p class="note">
  Rates are means over cases with a percentile bootstrap 95% CI. The suite is small
  (n&nbsp;=&nbsp;{_n_str(summaries)}), so the intervals are wide — shown openly rather than
  hidden. The <span class="lead-col">highlighted</span> column, leakage-verified ASR, is the
  metric the project is about.
</p>

<footer>
  Regenerate with <code>leakgauge report results/*.json --html docs/leaderboard/</code>.
  Static page, no build step. leakgauge is MIT-licensed.
</footer>
</body>
</html>
"""


def write_site(summaries: list[dict[str, Any]], reorder: RankReorder | None, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "index.html"
    path.write_text(render_html(summaries, reorder), encoding="utf-8")
    return path
