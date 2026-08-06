"""Run provenance: a results file has to say what produced it.

Every rate is stochastic — k seeded repeats plus a bootstrap — so a summary
without its run conditions cannot be compared against another one, and
CONTRIBUTING requires results to state seeds, hardware and wall-clock.

The determinism test is the one that matters: provenance is only worth
recording if quoting the same seed actually reproduces the numbers.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from leakgauge.adapters.stub import StubAdapter
from leakgauge.suite import (
    DEFAULT_BOOTSTRAP_ITERS,
    SCHEMA_VERSION,
    _provenance_line,
    cases_for_suite,
    format_summary_table,
    run_and_summarise,
    runtime_tag,
    stub_script_for,
)
from leakgauge.types import Case, ModelAdapter

REQUIRED_FIELDS = {
    "base_seed",
    "k",
    "seeds",
    "bootstrap_iters",
    "wall_clock_s",
    "runtime",
    "leakgauge_version",
}


def _stub(case: Case, seed: int) -> ModelAdapter:
    return StubAdapter(stub_script_for(case))


def _summary(**kwargs: object) -> dict:
    """A small, fast suite — provenance is suite-independent."""
    return run_and_summarise("toolrag", _stub, "stub:test", **kwargs)  # type: ignore[arg-type]


def test_summary_records_every_provenance_field() -> None:
    provenance = _summary()["provenance"]

    assert set(provenance) == REQUIRED_FIELDS
    assert provenance["bootstrap_iters"] == DEFAULT_BOOTSTRAP_ITERS
    assert provenance["leakgauge_version"] != ""


def test_provenance_reflects_the_seeds_actually_used() -> None:
    provenance = _summary(k=3, base_seed=7)["provenance"]

    assert provenance["base_seed"] == 7
    assert provenance["k"] == 3
    assert provenance["seeds"] == [7, 8, 9]


def test_provenance_reflects_a_non_default_bootstrap() -> None:
    """The iteration count shaped the interval, so it must not be a silent default."""
    provenance = _summary(bootstrap_iters=250)["provenance"]

    assert provenance["bootstrap_iters"] == 250


def test_schema_version_is_bumped_for_the_new_block() -> None:
    summary = _summary()

    assert summary["schema_version"] == SCHEMA_VERSION
    assert SCHEMA_VERSION >= 2


def test_v1_keys_are_unchanged() -> None:
    """Adding the block must not move anything an existing consumer reads."""
    summary = _summary(k=2, base_seed=1)

    assert summary["seeds"] == [1, 2]
    assert summary["k"] == 2
    assert isinstance(summary["wall_clock_s"], float)
    for key in ("model", "suite", "n_cases", "aggregate", "cost", "cases"):
        assert key in summary


def test_runtime_tag_carries_nothing_identifying() -> None:
    """A results file is committed, so the tag must be coarse."""
    import getpass
    import socket

    tag = runtime_tag()

    assert "python-" in tag
    assert socket.gethostname().lower() not in tag.lower()
    assert getpass.getuser().lower() not in tag.lower()


def test_two_runs_at_the_same_seed_produce_identical_rates() -> None:
    """The point of recording a seed: it has to reproduce.

    Everything except wall-clock — which is a measurement of the run, not an
    output of it — must match exactly.
    """
    first = _summary(k=3, base_seed=0)
    second = _summary(k=3, base_seed=0)

    assert first["aggregate"] == second["aggregate"]
    assert first["cases"] == second["cases"]

    for summary in (first, second):
        summary["wall_clock_s"] = 0.0
        summary["provenance"]["wall_clock_s"] = 0.0
    assert first == second


def test_a_different_base_seed_is_visible_in_provenance() -> None:
    """Otherwise two incomparable runs would look interchangeable."""
    a = _summary(k=2, base_seed=0)["provenance"]
    b = _summary(k=2, base_seed=100)["provenance"]

    assert a["seeds"] != b["seeds"]


def test_the_table_surfaces_provenance_next_to_the_rates() -> None:
    table = format_summary_table(_summary(k=2, base_seed=4))

    assert "base_seed=4" in table
    assert "k=2" in table
    assert f"bootstrap_iters={DEFAULT_BOOTSTRAP_ITERS}" in table
    assert "python-" in table


def test_provenance_line_falls_back_for_a_v1_summary() -> None:
    """An older results file has no block; a leaderboard must still render it."""
    legacy = {
        "schema_version": 1,
        "model": "old:model",
        "seeds": [0, 1],
        "k": 2,
        "wall_clock_s": 1.5,
    }

    line = _provenance_line(legacy)

    assert "base_seed=0" in line
    assert "k=2" in line
    assert "unrecorded" in line


def test_documented_repro_command_reproduces_the_committed_stub_numbers(
    tmp_path: Path,
) -> None:
    """The README's one-command repro path, asserted rather than described.

    Guards the claim itself: if the stub suite ever stops being deterministic,
    the documented command is wrong and this fails.
    """
    cases = cases_for_suite("all")
    first = run_and_summarise("all", _stub, "stub:demo", k=5, base_seed=0, cases=cases)
    second = run_and_summarise("all", _stub, "stub:demo", k=5, base_seed=0, cases=cases)

    assert first["aggregate"] == second["aggregate"]
    assert first["provenance"]["seeds"] == [0, 1, 2, 3, 4]

    # And it round-trips through the file the command writes.
    path = tmp_path / "stub_demo.json"
    path.write_text(json.dumps(first), encoding="utf-8")
    assert json.loads(path.read_text(encoding="utf-8"))["provenance"] == first["provenance"]


@pytest.mark.parametrize("field", sorted(REQUIRED_FIELDS))
def test_each_required_field_is_present(field: str) -> None:
    assert field in _summary()["provenance"]
