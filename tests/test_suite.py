"""Multi-case suite runner + results serialisation + rank-reorder report."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from leakgauge.adapters.stub import StubAdapter
from leakgauge.cases import DELAYED_CASE, build_environment
from leakgauge.cli import _adapter_factory, main
from leakgauge.runner import run_case
from leakgauge.scoring import crossings
from leakgauge.suite import (
    SCHEMA_VERSION,
    cases_for_suite,
    format_roster_markdown,
    load_summaries,
    load_summary,
    rank_reorder,
    roster_summary,
    run_and_summarise,
    stub_script_for,
    write_summary,
)
from leakgauge.types import Case, ExfilSpec, Response

_STUB = _adapter_factory("stub:demo")


def _summary(suite: str = "all", k: int = 3) -> dict[str, Any]:
    # Small bootstrap for test speed; the CI math is unchanged.
    return run_and_summarise(suite, _STUB, "stub:demo", k=k, bootstrap_iters=200)


def test_run_and_summarise_shape_and_rates() -> None:
    summary = _summary(k=3)

    assert summary["schema_version"] == SCHEMA_VERSION
    assert summary["model"] == "stub:demo"
    assert summary["k"] == 3
    assert summary["seeds"] == [0, 1, 2]
    assert summary["n_cases"] == len(cases_for_suite("all"))
    assert summary["wall_clock_s"] >= 0.0

    agg = summary["aggregate"]
    assert agg["hijack_asr"]["point"] == 1.0
    assert agg["leakage_asr"]["point"] == 1.0
    assert agg["utility_under_attack"]["point"] == 1.0

    assert len(summary["cases"]) == summary["n_cases"]
    row = summary["cases"][0]
    assert row["hijack_mean"] == 1.0 and row["hijack_std"] == 0.0
    assert row["leakage_mean"] == 1.0
    assert row["n"] == 3


def test_stub_run_has_zero_cost_block() -> None:
    cost = _summary(k=1)["cost"]
    assert cost["tokens_in"] == 0
    assert cost["tokens_out"] == 0
    assert cost["spend_usd"] == 0.0
    assert cost["priced"] is False  # stub is unpriced


def test_runner_accumulates_response_tokens() -> None:
    # Token capture rides on the Response path; the runner sums per completion.
    script = [
        Response(
            text="",
            tool_calls=[{"id": "c1", "name": "read_inbox", "args": {}}],
            tokens_in=100,
            tokens_out=10,
        ),
        Response(text="done", tool_calls=[], tokens_in=50, tokens_out=5),
    ]
    env = build_environment(DELAYED_CASE)
    record = run_case(DELAYED_CASE, env, StubAdapter(scripted=script), "stub:demo")
    assert record.tokens_in == 150
    assert record.tokens_out == 15


def test_write_summary_is_tracked_json_and_roundtrips(tmp_path: Path) -> None:
    summary = _summary()
    path = write_summary(summary, tmp_path)

    assert path.name == "stub_demo.json"  # ':' sanitised for the filename
    assert not path.name.endswith(".raw.json")  # tracked, not the gitignored form
    assert load_summary(path) == summary


def test_missing_stub_script_raises() -> None:
    orphan = Case(
        id="no-script-case",
        family="delayed",
        user_task="x",
        env_seed={},
        canary="LKG-" + "0" * 32,
        exfil_spec=ExfilSpec(attacker_addresses=["a@b.test"], external_tools=[]),
        utility_key="delayed_kickoff_scheduled",
    )
    with pytest.raises(KeyError):
        stub_script_for(orphan)


def test_load_summary_rejects_non_summary(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"not": "a summary"}), encoding="utf-8")
    with pytest.raises(ValueError):
        load_summary(bad)


def _fake_summary(
    model: str, hijack: float, leakage: float, utility: float | None = None
) -> dict[str, Any]:
    ci = lambda p: {"point": p, "lo": p, "hi": p}  # noqa: E731
    aggregate: dict[str, Any] = {"hijack_asr": ci(hijack), "leakage_asr": ci(leakage)}
    if utility is not None:
        aggregate["utility_under_attack"] = ci(utility)
    return {
        "schema_version": SCHEMA_VERSION,
        "model": model,
        "n_cases": 5,
        "aggregate": aggregate,
    }


def test_rank_reorder_detects_reordering() -> None:
    # A hijacks more but leaks less; B the reverse -> ranking flips.
    a = _fake_summary("model-a", hijack=0.9, leakage=0.2)
    b = _fake_summary("model-b", hijack=0.5, leakage=0.8)
    reorder = rank_reorder([a, b])

    assert reorder is not None
    assert reorder.models_by_hijack == ["model-a", "model-b"]
    assert reorder.models_by_leakage == ["model-b", "model-a"]
    assert reorder.hijack_ranks["model-a"] == 1
    assert reorder.leakage_ranks["model-a"] == 2
    assert reorder.kendall_tau < 0  # perfect anti-correlation on two models


def test_rank_reorder_needs_two_models() -> None:
    assert rank_reorder([_fake_summary("solo", 0.5, 0.5)]) is None


# --- machine-readable roster summary ----------------------------------------


def test_roster_summary_matches_the_computed_report() -> None:
    # A hijacks most but leaks least, so the two orderings disagree for every
    # model and the gap column has a different sign per row.
    summaries = [
        _fake_summary("model-a", hijack=0.9, leakage=0.2, utility=0.7),
        _fake_summary("model-b", hijack=0.5, leakage=0.8, utility=0.6),
        _fake_summary("model-c", hijack=0.1, leakage=0.1, utility=0.9),
    ]
    reorder = rank_reorder(summaries)
    assert reorder is not None
    roster = roster_summary(summaries, reorder)

    assert roster["n_models"] == 3
    assert roster["kendall_tau"] == reorder.kendall_tau
    assert roster["rank_crossings"] == crossings(reorder) == 2  # a and b swap; c stays
    # Rows are ordered worst-first by hijack, matching the reorder table.
    assert [m["model"] for m in roster["models"]] == reorder.models_by_hijack

    by_model = {m["model"]: m for m in roster["models"]}
    for summary in summaries:
        model = summary["model"]
        row = by_model[model]
        agg = summary["aggregate"]
        # Rates are the loaded values, CI and all -- nothing recomputed.
        assert row["hijack_asr"] == agg["hijack_asr"]
        assert row["leakage_asr"] == agg["leakage_asr"]
        assert row["utility_under_attack"] == agg["utility_under_attack"]
        assert row["n_cases"] == summary["n_cases"]
        assert row["gap"] == pytest.approx(agg["hijack_asr"]["point"] - agg["leakage_asr"]["point"])
        assert row["hijack_rank"] == reorder.hijack_ranks[model]
        assert row["leakage_rank"] == reorder.leakage_ranks[model]

    assert by_model["model-a"]["gap"] == pytest.approx(0.7)  # hijack overstates
    assert by_model["model-b"]["gap"] == pytest.approx(-0.3)  # leaks more than it hijacks


def test_roster_markdown_matches_the_roster_summary() -> None:
    summaries = [
        _fake_summary("model-a", hijack=0.9, leakage=0.2, utility=0.7),
        _fake_summary("model-b", hijack=0.5, leakage=0.8, utility=0.6),
    ]
    roster = roster_summary(summaries, rank_reorder(summaries))
    table = format_roster_markdown(roster)

    lines = table.splitlines()
    assert lines[0].startswith("| model |")
    # One header, one separator, one row per model -- no invented rows.
    body = [ln for ln in lines if ln.startswith("| model-")]
    assert len(body) == len(summaries)

    row_a = next(ln for ln in body if ln.startswith("| model-a "))
    assert "0.900 [0.900, 0.900]" in row_a  # point + CI, not just the point
    assert "0.200 [0.200, 0.200]" in row_a
    assert "+0.700" in row_a  # gap, signed
    assert f"{roster['kendall_tau']:.3f}" in table
    assert "2 of 2 model(s) change rank" in table


def test_roster_summary_leaves_an_unmeasured_metric_blank_not_zero() -> None:
    # _fake_summary omits utility_under_attack unless asked, mirroring a run
    # whose runner supplied no utility check.
    summaries = [
        _fake_summary("model-a", hijack=0.9, leakage=0.2),
        _fake_summary("model-b", hijack=0.5, leakage=0.8),
    ]
    roster = roster_summary(summaries, rank_reorder(summaries))

    assert all(m["utility_under_attack"] is None for m in roster["models"])
    # Survives a JSON round trip as null, so a consumer cannot read it as 0.
    reloaded = json.loads(json.dumps(roster))
    assert reloaded["models"][0]["utility_under_attack"] is None

    table = format_roster_markdown(roster)
    assert "| — |" in table
    assert "0.000" not in table  # never rendered as a measured zero


def test_roster_summary_single_model_has_no_ranks() -> None:
    roster = roster_summary(
        [_fake_summary("solo", 0.5, 0.5)], rank_reorder([_fake_summary("solo", 0.5, 0.5)])
    )

    assert roster["n_models"] == 1
    assert roster["kendall_tau"] is None
    assert roster["rank_crossings"] is None
    assert roster["models"][0]["hijack_rank"] is None
    assert "needs ≥2 model summaries" in format_roster_markdown(roster)


def test_report_writes_the_roster_summary_artifacts(tmp_path: Path) -> None:
    paths = []
    for model, hijack, leakage in (("stub:a", 0.9, 0.2), ("stub:b", 0.5, 0.8)):
        path = tmp_path / f"{model.replace(':', '_')}.json"
        path.write_text(json.dumps(_fake_summary(model, hijack, leakage)) + "\n", encoding="utf-8")
        paths.append(str(path))

    json_out = tmp_path / "nested" / "roster.json"  # parent is created on demand
    md_out = tmp_path / "roster.md"
    assert (
        main(["report", *paths, "--summary-json", str(json_out), "--summary-md", str(md_out)]) == 0
    )

    written = json.loads(json_out.read_text(encoding="utf-8"))
    expected = roster_summary(
        load_summaries(Path(p) for p in paths), rank_reorder(load_summaries(Path(p) for p in paths))
    )
    assert written == expected
    assert md_out.read_text(encoding="utf-8") == format_roster_markdown(expected) + "\n"


def test_report_without_summary_flags_writes_nothing(tmp_path: Path) -> None:
    path = tmp_path / "a.json"
    path.write_text(json.dumps(_fake_summary("stub:a", 0.9, 0.2)) + "\n", encoding="utf-8")
    assert main(["report", str(path)]) == 0
    assert list(tmp_path.iterdir()) == [path]


def test_cli_run_writes_results_and_report_reads_them(tmp_path: Path) -> None:
    assert (
        main(["--model", "stub:demo", "--suite", "all", "--k", "3", "--results-dir", str(tmp_path)])
        == 0
    )
    written = tmp_path / "stub_demo.json"
    assert written.exists()

    # Two model files -> the report subcommand runs the reorder end to end.
    second = tmp_path / "other.json"
    second.write_text(
        json.dumps(_fake_summary("stub:other", hijack=0.4, leakage=0.9)) + "\n", encoding="utf-8"
    )
    assert main(["report", str(written), str(second)]) == 0


def test_report_missing_file_errors_cleanly(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(["report", str(tmp_path / "nope.json")])
    assert rc == 2
    err = capsys.readouterr().err
    assert err.startswith("[leakgauge]")
    assert "Traceback" not in err


def test_report_malformed_json_errors_cleanly(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    rc = main(["report", str(bad)])
    assert rc == 2
    err = capsys.readouterr().err
    assert err.startswith("[leakgauge]")
    assert "Traceback" not in err


def test_report_non_summary_json_errors_cleanly(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    other = tmp_path / "other.json"
    other.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    rc = main(["report", str(other)])
    assert rc == 2
    err = capsys.readouterr().err
    assert err.startswith("[leakgauge]")
    assert "schema_version" in err
