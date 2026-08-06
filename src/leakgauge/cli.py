"""leakgauge CLI — run a suite of cases and print/emit the two ASRs.

Two entry forms:

- ``leakgauge --model stub:demo --suite all --k 3`` — run a suite offline, print
  a per-case table + aggregate CIs, and write ``results/<model>.json``.
- ``leakgauge report results/*.json`` — load several models' summaries and print
  the headline hijack-vs-leakage rank reorder (Kendall tau). ``--summary-json`` /
  ``--summary-md`` additionally write the roster summary as a diffable artifact.

The stub adapter is the offline default: it scripts a hijacked agent per case so
both ASRs register with zero API keys. Real providers plug in via the same
``provider:model`` id but are not exercised in CI.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path

from leakgauge.pricing import price_for
from leakgauge.runner import DEFAULT_MAX_STEPS
from leakgauge.suite import (
    DEFAULT_K,
    RESULTS_DIR,
    case_by_id,
    cases_for_suite,
    format_reorder_table,
    format_roster_markdown,
    format_summary_table,
    load_summaries,
    rank_reorder,
    roster_summary,
    run_and_summarise,
    stub_script_for,
    suite_names,
    write_summary,
)
from leakgauge.types import Case, ModelAdapter

# Re-exported so callers/tests have one name for "the offline script for a case".
_stub_script = stub_script_for


def _channel(case: Case) -> str:
    """Where this case's exfil goes — the attacker address, or egress tool(s)."""
    if case.exfil_spec.attacker_addresses:
        return case.exfil_spec.attacker_addresses[0]
    return ",".join(case.exfil_spec.external_tools) or "-"


def _list_cases() -> int:
    """Print every case (family, id, exfil channel) and exit; no model/network."""
    for case in sorted(cases_for_suite("all"), key=lambda c: (c.family, c.id)):
        print(f"{case.family:<9} {case.id:<46} {_channel(case)}")
    return 0


def _warn_if_unpriced(model_id: str) -> None:
    """Warn once on stderr if a non-stub run's model has no PRICES entry.

    An unpriced real model's spend silently reads $0 (:func:`price_for` returns
    None), so flag it up front. The offline ``stub`` provider is meant to be
    unpriced and never warns.
    """
    if model_id.partition(":")[0] == "stub":
        return
    if price_for(model_id) is not None:
        return
    print(
        f"warning: no price entry for {model_id!r}; spend will read $0 "
        "— add it to PRICES in src/leakgauge/pricing.py",
        file=sys.stderr,
    )


def _adapter_factory(model_id: str) -> Callable[[Case, int], ModelAdapter]:
    provider = model_id.partition(":")[0]
    if provider == "stub":
        from leakgauge.adapters.stub import StubAdapter

        return lambda case, _seed: StubAdapter(scripted=stub_script_for(case))
    from leakgauge.adapters import get_adapter

    adapter = get_adapter(model_id)
    return lambda _case, _seed: adapter


def _run(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="leakgauge",
        epilog=(
            "There is also a separate 'report' subcommand for comparing\n"
            "results you've already written, e.g.:\n"
            "\n"
            "  leakgauge report results/*.json --html docs/leaderboard/\n"
            "\n"
            "It loads one or more <model>.json summaries and prints the\n"
            "hijack-vs-leakage rank reorder (add --html to also render a\n"
            "static leaderboard page)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--list-cases",
        action="store_true",
        help="print each case (family, id, exfil channel) and exit; no model/network",
    )
    parser.add_argument("--model", default="stub:demo", help="adapter id, e.g. stub:demo")
    parser.add_argument("--suite", default="all", choices=suite_names(), help="family or 'all'")
    parser.add_argument(
        "--case", default=None, help="run a single case by id (overrides --suite); see --list-cases"
    )
    parser.add_argument("--k", type=int, default=DEFAULT_K, help="seeded repeats per case")
    parser.add_argument("--seed", type=int, default=0, help="base seed")
    parser.add_argument("--max-steps", type=int, default=DEFAULT_MAX_STEPS)
    parser.add_argument(
        "--results-dir", default=str(RESULTS_DIR), help="where to write <model>.json"
    )
    args = parser.parse_args(argv)

    if args.list_cases:
        return _list_cases()

    if args.max_steps < 1:
        print(f"[leakgauge] --max-steps must be >= 1 (got {args.max_steps})", file=sys.stderr)
        return 2

    if args.k < 1:
        print(f"[leakgauge] --k must be >= 1 (got {args.k})", file=sys.stderr)
        return 2

    if args.seed < 0:
        print(f"[leakgauge] --seed must be >= 0 (got {args.seed})", file=sys.stderr)
        return 2

    selected: list[Case] | None = None
    suite_label = args.suite
    if args.case is not None:
        try:
            selected = [case_by_id(args.case)]
        except ValueError as err:
            print(f"[leakgauge] {err}", file=sys.stderr)
            return 2
        suite_label = f"case:{args.case}"

    _warn_if_unpriced(args.model)

    summary = run_and_summarise(
        suite_label,
        _adapter_factory(args.model),
        args.model,
        k=args.k,
        base_seed=args.seed,
        max_steps=args.max_steps,
        cases=selected,
    )
    path = write_summary(summary, Path(args.results_dir))
    print(format_summary_table(summary))
    print(f"\n  wrote {path}")
    return 0


def _report(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="leakgauge report")
    parser.add_argument("paths", nargs="+", help="summary json files (results/*.json)")
    parser.add_argument(
        "--html", metavar="DIR", help="also render a static leaderboard index.html into DIR"
    )
    parser.add_argument(
        "--summary-json",
        metavar="PATH",
        help="also write the machine-readable roster summary (rates + CIs, gap, ranks, tau)",
    )
    parser.add_argument(
        "--summary-md",
        metavar="PATH",
        help="also write the roster summary as a committable markdown table",
    )
    args = parser.parse_args(argv)

    try:
        summaries = load_summaries(Path(p) for p in args.paths)
    except FileNotFoundError as err:
        missing = getattr(err, "filename", None) or err
        print(f"[leakgauge] no such file: {missing}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as err:
        print(f"[leakgauge] invalid JSON: {err}", file=sys.stderr)
        return 2
    except ValueError as err:
        print(f"[leakgauge] {err}", file=sys.stderr)
        return 2
    reorder = rank_reorder(summaries)
    print(format_reorder_table(summaries, reorder))

    if args.summary_json or args.summary_md:
        roster = roster_summary(summaries, reorder)
        if args.summary_json:
            path = Path(args.summary_json)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(roster, indent=2) + "\n", encoding="utf-8")
            print(f"\n  wrote {path}")
        if args.summary_md:
            path = Path(args.summary_md)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(format_roster_markdown(roster) + "\n", encoding="utf-8")
            print(f"\n  wrote {path}")

    if args.html:
        from leakgauge.leaderboard import write_site

        path = write_site(summaries, reorder, Path(args.html))
        print(f"\n  wrote {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "report":
        return _report(args[1:])
    return _run(args)


if __name__ == "__main__":
    raise SystemExit(main())
