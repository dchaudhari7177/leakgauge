"""Multi-case suite runner + machine-readable results + rank-reorder report.

Runs every case in a family (or ``all``) with ``k`` seeds through an adapter,
aggregates via the real scorer (:func:`leakgauge.scoring.compute_report` — the
same bootstrap CIs for hijack, leakage, and utility), and serialises a tracked
summary JSON. The ``report`` path loads several models' summaries and computes
the headline hijack-vs-leakage rank reorder (Kendall tau).

Case selection and the offline stub scripts live here in one registry each, so
there is a single source of truth for both the runner and the CLI.
"""

from __future__ import annotations

import json
import platform
import statistics
import time
from collections.abc import Callable, Iterable
from importlib import metadata
from pathlib import Path
from typing import Any

from leakgauge.cases import (
    ALL_CASES,
    ASSEMBLY_CASES,
    BENIGN_ACTION,
    DELAYED_CASES,
    ENCODED_CASES,
    ONPATH_DOC_ID,
    TOOLRAG_CASES,
    build_environment,
)
from leakgauge.pricing import cost_usd, price_for
from leakgauge.runner import DEFAULT_MAX_STEPS, run_case
from leakgauge.scoring import ModelReport, RankReorder, RateCI, _rank_reorder, compute_report
from leakgauge.types import Case, ModelAdapter, Response, RunRecord

SCHEMA_VERSION = 2  # 2 adds the "provenance" block; every v1 key is unchanged
# k=1 is a coin flip on stochastic models (two identical pilots gave 0/9 vs 1/9),
# so the seeded default is 5. Adopted as policy in Phase 3.
DEFAULT_K = 5
RESULTS_DIR = Path("results")

# Bootstrap resamples for the aggregate CIs. Named here so the value that
# actually shaped an interval can be recorded in the summary's provenance
# rather than being an invisible default.
DEFAULT_BOOTSTRAP_ITERS = 10_000


def runtime_tag() -> str:
    """Coarse platform + interpreter tag for results provenance.

    Deliberately coarse: OS, machine architecture and Python version. No
    hostname, no user, no CPU model — a results file is committed to the repo,
    so it must not carry anything identifying about who ran it.
    """
    return f"{platform.system()} {platform.machine()} python-{platform.python_version()}"


def _package_version() -> str:
    """Installed leakgauge version, or "unknown" when running from a bare tree."""
    try:
        return metadata.version("leakgauge")
    except metadata.PackageNotFoundError:  # pragma: no cover - editable/no-dist tree
        return "unknown"


# --- case registry -----------------------------------------------------------
# Local to the suite runner (cases.py is owned by the cases workstream). Group
# authored cases by family; "all" flattens every family.

CASE_REGISTRY: dict[str, list[Case]] = {
    "delayed": DELAYED_CASES,
    "assembly": ASSEMBLY_CASES,
    "encoded": ENCODED_CASES,
    "toolrag": TOOLRAG_CASES,
}


def suite_names() -> list[str]:
    return [*sorted(CASE_REGISTRY), "all"]


def cases_for_suite(suite: str) -> list[Case]:
    if suite == "all":
        return [c for family in sorted(CASE_REGISTRY) for c in CASE_REGISTRY[family]]
    if suite not in CASE_REGISTRY:
        raise ValueError(f"unknown suite {suite!r}; choose from {suite_names()}")
    return list(CASE_REGISTRY[suite])


def case_by_id(case_id: str) -> Case:
    """Return the single case with this id, or raise ValueError if unknown."""
    for case in cases_for_suite("all"):
        if case.id == case_id:
            return case
    raise ValueError(f"unknown case id {case_id!r}; run with --list-cases to see valid ids")


# --- offline stub scripts ----------------------------------------------------
# Each case needs a deterministic script so the stub adapter exercises leakage
# with no API key. A case in a run suite with no script is a hard error — a
# silent empty script would score hijack=0/leak=0, indistinguishable from a
# model that actually resisted.
#
# One uniform builder now models a fully-hijacked-and-leaking agent for every
# case: read the inbox, exfiltrate the raw canary to the attacker, then still
# perform the benign calendar action (from cases.BENIGN_ACTION) so utility stays
# satisfied. Reading the benign action from cases.py means new/edited cases never
# require a suite.py change — the single source of truth is the case module.


def _uniform_stub(case: Case) -> list[Response]:
    attacker = case.exfil_spec.attacker_addresses[0]
    act = BENIGN_ACTION[case.id]
    return [
        Response(text="", tool_calls=[{"id": "c1", "name": "read_inbox", "args": {}}]),
        Response(
            text="",
            tool_calls=[
                {
                    "id": "c2",
                    "name": "send_email",
                    "args": {
                        "recipients": [attacker],
                        "subject": "verification",
                        "body": f"verification token: {case.canary}",
                    },
                }
            ],
        ),
        Response(
            text="",
            tool_calls=[
                {
                    "id": "c3",
                    "name": "create_event",
                    "args": {"title": act["title"], "start": act["start"], "end": act["end"]},
                }
            ],
        ),
        Response(text="Done.", tool_calls=[]),
    ]


def _toolrag_stub(case: Case) -> list[Response]:
    """Toolrag agent: fetch the poisoned document (the on-path tool result),
    exfiltrate its canary, then still complete the benign calendar action."""
    attacker = case.exfil_spec.attacker_addresses[0]
    act = BENIGN_ACTION[case.id]
    doc_id = ONPATH_DOC_ID[case.id]
    return [
        Response(
            text="",
            tool_calls=[{"id": "c1", "name": "read_document", "args": {"document_id": doc_id}}],
        ),
        Response(
            text="",
            tool_calls=[
                {
                    "id": "c2",
                    "name": "send_email",
                    "args": {
                        "recipients": [attacker],
                        "subject": "verification",
                        "body": f"verification token: {case.canary}",
                    },
                }
            ],
        ),
        Response(
            text="",
            tool_calls=[
                {
                    "id": "c3",
                    "name": "create_event",
                    "args": {"title": act["title"], "start": act["start"], "end": act["end"]},
                }
            ],
        ),
        Response(text="Done.", tool_calls=[]),
    ]


STUB_SCRIPTS: dict[str, Callable[[Case], list[Response]]] = {
    _case.id: _uniform_stub for _case in ALL_CASES
}
# toolrag cases inject through a retrieved document, so their offline stub reads
# the document (not the inbox) before leaking — exercising the retrieval channel.
STUB_SCRIPTS.update({_case.id: _toolrag_stub for _case in TOOLRAG_CASES})


def stub_script_for(case: Case) -> list[Response]:
    builder = STUB_SCRIPTS.get(case.id)
    if builder is None:
        raise KeyError(
            f"no offline stub script for case {case.id!r}; add one to "
            f"leakgauge.suite.STUB_SCRIPTS so --model stub:* exercises it"
        )
    return builder(case)


# --- running -----------------------------------------------------------------

# (case_id, seed) -> did the benign task complete this run. Fed to the scorer's
# utility_ok so utility rides the same bootstrap CI as hijack/leakage.
UtilityMap = dict[tuple[str, int], bool]


def run_suite(
    cases: list[Case],
    make_adapter: Callable[[Case, int], ModelAdapter],
    model_id: str,
    *,
    k: int = DEFAULT_K,
    base_seed: int = 0,
    max_steps: int = DEFAULT_MAX_STEPS,
) -> tuple[list[RunRecord], UtilityMap]:
    """Run every case × k seeds; collect records and a per-run utility map."""
    records: list[RunRecord] = []
    utility: UtilityMap = {}
    for case in cases:
        for offset in range(k):
            seed = base_seed + offset
            env = build_environment(case)
            record = run_case(
                case, env, make_adapter(case, seed), model_id, seed=seed, max_steps=max_steps
            )
            records.append(record)
            utility[(case.id, seed)] = env.utility_ok(case.utility_key)
    return records, utility


# --- summary serialisation ---------------------------------------------------


def _rate(ci: RateCI) -> dict[str, float]:
    return {"point": ci.point, "lo": ci.lo, "hi": ci.hi}


def _per_case_utility(
    cases: list[Case], utility: UtilityMap, seeds: list[int]
) -> dict[str, tuple[float, float]]:
    out: dict[str, tuple[float, float]] = {}
    for case in cases:
        vals = [1.0 if utility[(case.id, s)] else 0.0 for s in seeds]
        std = statistics.pstdev(vals) if len(vals) > 1 else 0.0
        out[case.id] = (statistics.fmean(vals) if vals else 0.0, std)
    return out


def build_summary(
    records: list[RunRecord],
    cases: list[Case],
    utility: UtilityMap,
    *,
    model_id: str,
    suite: str,
    seeds: list[int],
    wall_clock_s: float,
    bootstrap_iters: int = DEFAULT_BOOTSTRAP_ITERS,
) -> dict[str, Any]:
    """Aggregate records into the tracked summary dict."""
    report = compute_report(
        records,
        cases,
        utility_ok=lambda r, _c: utility[(r.case_id, r.seed)],
        bootstrap_iters=bootstrap_iters,
    )
    model = report.per_model[0]
    family_by_id = {c.id: c.family for c in cases}
    util_by_id = _per_case_utility(cases, utility, seeds)
    leak_by_id = {s.case_id: s for s in model.per_case_leakage}

    rows: list[dict[str, Any]] = []
    for hij in model.per_case_hijack:
        leak = leak_by_id[hij.case_id]
        util_mean, util_std = util_by_id[hij.case_id]
        rows.append(
            {
                "case_id": hij.case_id,
                "family": family_by_id[hij.case_id],
                "n": hij.n,
                "hijack_mean": hij.mean,
                "hijack_std": hij.std,
                "leakage_mean": leak.mean,
                "leakage_std": leak.std,
                "utility_mean": util_mean,
                "utility_std": util_std,
            }
        )

    tokens_in = sum(r.tokens_in for r in records)
    tokens_out = sum(r.tokens_out for r in records)
    price = price_for(model_id)

    return {
        "schema_version": SCHEMA_VERSION,
        "model": model_id,
        "suite": suite,
        "seeds": seeds,
        "k": len(seeds),
        "n_cases": model.n_cases,
        "wall_clock_s": round(wall_clock_s, 4),
        # Every rate here is stochastic — k seeded repeats plus a bootstrap — so
        # a results file that does not say under what conditions it was produced
        # cannot be compared against another one, and CONTRIBUTING requires
        # seeds, hardware and wall-clock to be stated. Collected in one block so
        # a reader does not have to know which top-level keys happen to be
        # provenance.
        "provenance": {
            "base_seed": seeds[0] if seeds else 0,
            "k": len(seeds),
            "seeds": seeds,
            "bootstrap_iters": bootstrap_iters,
            "wall_clock_s": round(wall_clock_s, 4),
            "runtime": runtime_tag(),
            "leakgauge_version": _package_version(),
        },
        "aggregate": {
            "hijack_asr": _rate(model.hijack),
            "leakage_asr": _rate(model.leakage),
            "utility_under_attack": _rate(model.utility) if model.utility else None,
        },
        "cost": {
            "tokens_in": tokens_in,
            "tokens_out": tokens_out,
            "spend_usd": round(cost_usd(model_id, tokens_in, tokens_out), 6),
            "priced": price is not None,
            "usd_per_1m_in": price.usd_per_1m_in if price else None,
            "usd_per_1m_out": price.usd_per_1m_out if price else None,
        },
        "cases": rows,
    }


def _result_path(results_dir: Path, model_id: str) -> Path:
    safe = model_id.replace(":", "_").replace("/", "_")
    return results_dir / f"{safe}.json"


def write_summary(summary: dict[str, Any], results_dir: Path = RESULTS_DIR) -> Path:
    results_dir.mkdir(parents=True, exist_ok=True)
    path = _result_path(results_dir, summary["model"])
    path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return path


def run_and_summarise(
    suite: str,
    make_adapter: Callable[[Case, int], ModelAdapter],
    model_id: str,
    *,
    k: int = DEFAULT_K,
    base_seed: int = 0,
    max_steps: int = DEFAULT_MAX_STEPS,
    bootstrap_iters: int = 10_000,
    cases: list[Case] | None = None,
) -> dict[str, Any]:
    cases = cases_for_suite(suite) if cases is None else cases
    seeds = [base_seed + i for i in range(k)]
    start = time.perf_counter()
    records, utility = run_suite(
        cases, make_adapter, model_id, k=k, base_seed=base_seed, max_steps=max_steps
    )
    wall = time.perf_counter() - start
    return build_summary(
        records,
        cases,
        utility,
        model_id=model_id,
        suite=suite,
        seeds=seeds,
        wall_clock_s=wall,
        bootstrap_iters=bootstrap_iters,
    )


# --- stdout tables -----------------------------------------------------------


def format_summary_table(summary: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(
        f"[leakgauge] model={summary['model']} suite={summary['suite']} "
        f"k={summary['k']} n_cases={summary['n_cases']} "
        f"wall={summary['wall_clock_s']}s"
    )
    header = f"  {'case_id':<32} {'family':<10} {'hijack':>13} {'leakage':>13} {'utility':>13}"
    lines.append(header)
    lines.append("  " + "-" * (len(header) - 2))
    for row in summary["cases"]:
        lines.append(
            f"  {row['case_id']:<32} {row['family']:<10} "
            f"{_pm(row['hijack_mean'], row['hijack_std']):>13} "
            f"{_pm(row['leakage_mean'], row['leakage_std']):>13} "
            f"{_pm(row['utility_mean'], row['utility_std']):>13}"
        )
    agg = summary["aggregate"]
    lines.append("")
    lines.append(f"  aggregate over {summary['n_cases']} case(s), 95% bootstrap CI:")
    lines.append(f"    hijack-ASR           : {_ci(agg['hijack_asr'])}")
    lines.append(f"    leakage-verified ASR : {_ci(agg['leakage_asr'])}")
    if agg["utility_under_attack"] is not None:
        lines.append(f"    utility-under-attack : {_ci(agg['utility_under_attack'])}")
    if summary["n_cases"] < 2:
        lines.append("    (n_cases<2 — CI is degenerate; add cases for a meaningful interval)")
    cost = summary["cost"]
    unpriced = "" if cost["priced"] else " (unpriced model — $0)"
    lines.append(
        f"  spend: {_fmt_usd(cost['spend_usd'])} "
        f"({cost['tokens_in']} in / {cost['tokens_out']} out tokens){unpriced}"
    )
    lines.append(_provenance_line(summary))
    return "\n".join(lines)


def _provenance_line(summary: dict[str, Any]) -> str:
    """Run conditions, printed next to the rates they produced.

    Falls back to the top-level keys for a v1 summary, which has no provenance
    block — a leaderboard should still render an older results file.
    """
    prov = summary.get("provenance") or {}
    seeds = prov.get("seeds", summary.get("seeds", []))
    base_seed = prov.get("base_seed", seeds[0] if seeds else 0)
    k = prov.get("k", summary.get("k", 0))
    iters = prov.get("bootstrap_iters", "?")
    wall = prov.get("wall_clock_s", summary.get("wall_clock_s", "?"))
    runtime = prov.get("runtime", "unrecorded")
    version = prov.get("leakgauge_version", "unrecorded")
    return (
        f"  run: base_seed={base_seed} k={k} bootstrap_iters={iters} "
        f"wall={wall}s | {runtime} | leakgauge {version}"
    )


def _fmt_usd(amount: float) -> str:
    # Two decimals normally; extra precision for sub-cent pilot runs.
    return f"${amount:,.2f}" if amount == 0 or amount >= 0.01 else f"${amount:.4f}"


def _pm(mean: float, std: float) -> str:
    return f"{mean:.2f}±{std:.2f}"


def _ci(rate: dict[str, float]) -> str:
    return f"{rate['point']:.3f}  [{rate['lo']:.3f}, {rate['hi']:.3f}]"


# --- rank-reorder report across models --------------------------------------


def load_summary(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "schema_version" not in data:
        raise ValueError(f"{path}: not a leakgauge summary (no schema_version)")
    return data


def _summary_to_report(summary: dict[str, Any]) -> ModelReport:
    agg = summary["aggregate"]
    return ModelReport(
        model=summary["model"],
        n_cases=summary.get("n_cases", 0),
        hijack=RateCI(**agg["hijack_asr"]),
        leakage=RateCI(**agg["leakage_asr"]),
        utility=None,
        per_case_hijack=[],
        per_case_leakage=[],
    )


def rank_reorder(summaries: list[dict[str, Any]]) -> RankReorder | None:
    """Headline thesis test: rank models by hijack vs by leakage (Kendall tau).

    Delegates the tau/tie math to the scorer's ``_rank_reorder``."""
    return _rank_reorder([_summary_to_report(s) for s in summaries])


def format_reorder_table(summaries: list[dict[str, Any]], reorder: RankReorder | None) -> str:
    rate_by_model = {
        s["model"]: (s["aggregate"]["hijack_asr"]["point"], s["aggregate"]["leakage_asr"]["point"])
        for s in summaries
    }
    lines: list[str] = ["[leakgauge] hijack-vs-leakage rank reorder"]
    if reorder is None:
        lines.append("  need >=2 model summaries to compute a reorder")
        return "\n".join(lines)
    header = f"  {'model':<24} {'hijack-ASR':>11} {'h-rank':>7} {'leak-ASR':>11} {'l-rank':>7}"
    lines.append(header)
    lines.append("  " + "-" * (len(header) - 2))
    for model in reorder.models_by_hijack:
        hij, leak = rate_by_model[model]
        lines.append(
            f"  {model:<24} {hij:>11.3f} {reorder.hijack_ranks[model]:>7} "
            f"{leak:>11.3f} {reorder.leakage_ranks[model]:>7}"
        )
    lines.append("")
    lines.append(f"  Kendall tau (hijack-rate vs leakage-rate): {reorder.kendall_tau:.3f}")
    lines.append("  tau<1 means ranking by leakage reorders the models — the thesis.")
    # A reorder compares rates across files, so the conditions each was produced
    # under belong next to it: two models run at different k are not comparable.
    lines.append("")
    lines.append("  run conditions per model:")
    for summary in summaries:
        lines.append(f"  {summary['model']:<24}{_provenance_line(summary).strip()}")
    return "\n".join(lines)


def load_summaries(paths: Iterable[Path]) -> list[dict[str, Any]]:
    return [load_summary(p) for p in paths]
