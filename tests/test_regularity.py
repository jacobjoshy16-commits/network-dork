"""The regularity metric and the per-metric thresholds it needed.

Beaconing is a rhythm, not a volume. These tests pin both the measure and
the reason it is scaled the way it is, since a bounded form was tried first
and failed in evaluation.
"""

import pytest

from network_dork.config import ForecastSettings
from network_dork.regularity import MAX_REGULARITY, rolling_regularity


def test_a_constant_rate_is_maximally_regular():
    assert rolling_regularity([5.0] * 12, 12)[-1] == MAX_REGULARITY


def test_bursty_traffic_scores_far_below_a_steady_rate():
    steady = rolling_regularity([10.0, 10.2, 9.8, 10.1] * 3, 12)[-1]
    bursty = rolling_regularity([1.0, 40.0, 0.0, 3.0] * 3, 12)[-1]
    assert steady > bursty * 5


def test_an_idle_host_is_absent_not_regular():
    """Silence must not read as rhythm, or every quiet night gets flagged."""
    assert rolling_regularity([0.0] * 12, 12) == [0.0] * 12


def test_the_measure_keeps_a_multiplicative_dynamic_range():
    """Why 1/CV and not 1/(1+CV).

    The bounded form compressed everything into (0, 1], so a beacon moved
    the value by less than the scorer's band floor and vanished. The
    reciprocal keeps beacon-like regularity an order of magnitude above
    ordinary traffic, which the existing scoring can see.
    """
    beacon = rolling_regularity([10.0, 10.3, 9.7, 10.1] * 3, 12)[-1]
    ordinary = rolling_regularity([4.0, 9.0, 2.0, 11.0] * 3, 12)[-1]
    assert beacon / ordinary > 5


def test_short_prefixes_do_not_invent_a_value():
    assert rolling_regularity([7.0, 7.0], 12)[0] == 0.0


def test_window_and_cap_are_validated():
    with pytest.raises(ValueError):
        rolling_regularity([1.0, 2.0], 1)
    with pytest.raises(ValueError):
        rolling_regularity([1.0, 2.0], 2, cap=0)


# --- per-metric thresholds --------------------------------------------------


def test_every_shipped_metric_has_its_own_threshold():
    """A global bar is set by the noisiest metric and buries the quietest.

    Measured benign maxima on the corpus ranged from 3.5 (conn_regularity)
    to 22.4 (bytes_out); one threshold at 24 hid beaconing entirely.
    """
    thresholds = ForecastSettings().min_score_by_metric
    assert set(thresholds) == {
        "conn_count",
        "bytes_out",
        "distinct_destinations",
        "conn_regularity",
    }
    assert thresholds["conn_regularity"] < thresholds["bytes_out"], (
        "the quiet metric must not inherit the noisy metric's bar"
    )
