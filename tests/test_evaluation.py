"""The evaluation harness, and the thresholds it justifies.

These tests guard the conclusions in docs/evaluation.md. If scoring changes,
the numbers here move and the documented operating point has to be re-derived
rather than quietly drifting.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from network_dork.anomaly import Deviation, SeasonalNaiveForecaster, most_deviant
from network_dork.evaluation import (
    Corpus,
    EvaluationPoint,
    LabelWindow,
    _has_usable_history,
    attacks_found,
    evaluate,
    tally,
)

CORPUS = Path("fixtures/timeseries")
NOW = datetime(2025, 1, 1, tzinfo=timezone.utc)


def point(score: float, malicious: bool, category: str | None) -> EvaluationPoint:
    return EvaluationPoint(
        entity="10.0.0.1",
        metric="conn_count",
        alert_time=NOW,
        window_start=NOW - timedelta(hours=6),
        malicious=malicious,
        category=category,
        peak_score=score,
    )


# --- corpus integrity -------------------------------------------------------


def test_corpus_has_both_malicious_and_benign_windows():
    """A corpus of only attacks cannot measure false positives."""
    corpus = Corpus.load(CORPUS)
    malicious = [item for item in corpus.labels if item.malicious]
    benign = [item for item in corpus.labels if not item.malicious]
    assert malicious, "no malicious windows to detect"
    assert benign, "no benign confounders: false positives are unmeasurable"
    assert {item.category for item in malicious} == {
        "c2_beaconing",
        "data_exfiltration",
        "internal_scanning",
    }


def test_corpus_hosts_all_carry_every_metric():
    corpus = Corpus.load(CORPUS)
    for entity in corpus.hosts:
        for metric in corpus.metrics:
            values = corpus.series(entity, metric)
            assert len(values) == 8640, f"{entity}/{metric} is the wrong length"


def test_onboarded_host_is_refused_rather_than_forecast():
    """The cold-start host must be skipped, not guessed at."""
    corpus = Corpus.load(CORPUS)
    early = corpus.series("10.10.0.23", "conn_count")[:4032]
    assert not _has_usable_history(
        early, min_observations=100, min_span_fraction=0.5
    )


# --- scoreboard arithmetic --------------------------------------------------


def test_benign_confounders_count_as_negatives_not_as_unlabelled():
    points = [
        point(50.0, True, "data_exfiltration"),
        point(50.0, False, "scheduled_backup"),
        point(1.0, False, None),
    ]
    board = tally(points, threshold=24.0)
    assert board.true_positives == 1
    assert board.false_positives == 1
    assert board.confounder_flags == 1
    assert board.confounder_total == 1
    assert board.precision == 0.5


def test_attacks_found_reports_per_campaign_not_per_point():
    """One detection anywhere in a campaign is a find."""
    points = [
        point(0.0, True, "c2_beaconing"),
        point(0.0, True, "c2_beaconing"),
        point(99.0, True, "c2_beaconing"),
        point(0.0, True, "data_exfiltration"),
    ]
    found = attacks_found(points, threshold=24.0)
    assert found["c2_beaconing"] is True
    assert found["data_exfiltration"] is False


def test_empty_scoreboard_does_not_divide_by_zero():
    board = tally([], threshold=1.0)
    assert board.precision == 0.0
    assert board.recall == 0.0
    assert board.f1 == 0.0
    assert board.false_positive_rate == 0.0
    assert board.confounder_rate == 0.0


# --- the documented operating point -----------------------------------------


@pytest.fixture(scope="module")
def baseline_points():
    corpus = Corpus.load(CORPUS)
    points, _ = evaluate(
        SeasonalNaiveForecaster(period_buckets=288), corpus
    )
    return points


def test_shipped_threshold_flags_no_benign_window(baseline_points):
    """The claim the shipped default rests on."""
    board = tally(baseline_points, threshold=24.0)
    assert board.confounder_flags == 0
    assert board.false_positives == 0
    assert board.precision == 1.0


def test_shipped_threshold_still_finds_volume_shaped_attacks(baseline_points):
    found = attacks_found(baseline_points, threshold=24.0)
    assert found["data_exfiltration"] is True
    assert found["internal_scanning"] is True


def test_beaconing_is_missed_and_that_is_recorded_not_hidden(baseline_points):
    """Documented limitation, asserted so it cannot be quietly forgotten.

    Low-rate beaconing is a periodicity anomaly, not a volume anomaly, and
    the seasonal-naive baseline compares magnitudes only. This is the gap a
    learned forecaster would have to close to justify its dependencies.
    """
    found = attacks_found(baseline_points, threshold=24.0)
    assert found["c2_beaconing"] is False


def test_a_low_threshold_would_flag_benign_windows(baseline_points):
    """Why min_score is not near zero.

    The first run of this harness used 1.0 and reported a 64% false-positive
    rate. This asserts the trap is still there, so nobody lowers the default
    without seeing the cost.
    """
    loose = tally(baseline_points, threshold=1.0)
    assert loose.false_positive_rate > 0.5
    assert loose.precision < 0.05


# --- evidence selection -----------------------------------------------------


def test_min_score_suppresses_ordinary_band_exceedances():
    """An 80% band puts ~20% of buckets outside it; those are not evidence."""
    deviations = [
        Deviation(
            timestamp=NOW + timedelta(minutes=5 * index),
            actual=10.0,
            predicted=8.0,
            lower=7.0,
            upper=9.0,
            score=score,
        )
        for index, score in enumerate([0.5, 1.2, 2.6, 3.0])
    ]
    assert most_deviant(deviations, 5, min_score=24.0) == []
    assert len(most_deviant(deviations, 5, min_score=0.0)) == 4


def test_min_score_admits_a_genuine_deviation():
    deviations = [
        Deviation(
            timestamp=NOW,
            actual=400.0,
            predicted=8.0,
            lower=7.0,
            upper=9.0,
            score=48.0,
        )
    ]
    assert len(most_deviant(deviations, 5, min_score=24.0)) == 1


def test_negative_min_score_is_rejected():
    with pytest.raises(ValueError):
        most_deviant([], 5, min_score=-1.0)
