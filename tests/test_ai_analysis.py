import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from collections import Counter
from ai_analysis import fallback_analysis, analyse, _health_label


# --- _health_label ---

def test_health_critical():
    assert _health_label({"CRITICAL": 1, "ERROR": 0, "WARNING": 0, "UNKNOWN": 0}, 1) == "CRITICAL"

def test_health_unhealthy_high_error_rate():
    # error rate 40% > 30% → UNHEALTHY (worse than DEGRADED)
    assert _health_label({"CRITICAL": 0, "ERROR": 40, "WARNING": 60, "UNKNOWN": 0}, 100) == "UNHEALTHY"

def test_health_degraded_some_errors():
    # ERROR=5, WARNING=10, total=15 → error rate 33% > 30% → UNHEALTHY
    assert _health_label({"CRITICAL": 0, "ERROR": 5, "WARNING": 10, "UNKNOWN": 0}, 15) == "UNHEALTHY"

def test_health_degraded_low_error_count():
    # only 2 errors out of 50 total → 4% error rate → DEGRADED (not UNHEALTHY)
    assert _health_label({"CRITICAL": 0, "ERROR": 2, "WARNING": 48, "UNKNOWN": 0}, 50) == "DEGRADED"

def test_health_degraded_many_warnings():
    assert _health_label({"CRITICAL": 0, "ERROR": 0, "WARNING": 20, "UNKNOWN": 0}, 20) == "DEGRADED"

def test_health_healthy():
    assert _health_label({"CRITICAL": 0, "ERROR": 0, "WARNING": 3, "UNKNOWN": 0}, 3) == "HEALTHY"


# --- fallback_analysis ---

def test_empty_input():
    result = fallback_analysis(Counter(), {"CRITICAL": 0, "ERROR": 0, "WARNING": 0, "UNKNOWN": 0})
    assert result == "No issues detected."

def test_primary_issue_shown_when_dominant():
    patterns = Counter({"connection timeout after 30s": 50, "disk error": 5})
    severity = {"CRITICAL": 0, "ERROR": 10, "WARNING": 45, "UNKNOWN": 0}
    result = fallback_analysis(patterns, severity)
    assert "Primary issue" in result
    assert "connection timeout" in result

def test_primary_issue_hidden_when_not_dominant():
    # top pattern is only 10% — should not appear as "Primary issue"
    patterns = Counter({f"pattern_{i}": 10 for i in range(10)})
    severity = {"CRITICAL": 0, "ERROR": 50, "WARNING": 50, "UNKNOWN": 0}
    result = fallback_analysis(patterns, severity)
    assert "Primary issue" not in result

def test_dominant_service_shown():
    services = {"sshd": [""] * 80, "kernel": [""] * 20}
    severity = {"CRITICAL": 0, "ERROR": 50, "WARNING": 50, "UNKNOWN": 0}
    result = fallback_analysis(Counter({"login failed": 100}), severity, services=services)
    assert "sshd" in result

def test_dominant_service_hidden_when_spread():
    # three equal services → none reaches 40% threshold
    services = {"sshd": [""] * 33, "kernel": [""] * 33, "systemd": [""] * 34}
    severity = {"CRITICAL": 0, "ERROR": 50, "WARNING": 50, "UNKNOWN": 0}
    result = fallback_analysis(Counter({"login failed": 100}), severity, services=services)
    assert "Noisiest service" not in result

def test_recommendation_present():
    patterns = Counter({"WSL ERROR: getaddrinfo() failed": 30})
    severity = {"CRITICAL": 0, "ERROR": 10, "WARNING": 20, "UNKNOWN": 0}
    result = fallback_analysis(patterns, severity)
    assert "Recommendation:" in result

def test_real_v3_data():
    patterns = Counter({
        'WARNING Daemon: could not connect to Windows Agent...': 33,
        "WSL (270) ERROR: CheckConnection: getaddrinfo() failed: -5": 6,
    })
    severity = {"CRITICAL": 0, "ERROR": 21, "WARNING": 52, "UNKNOWN": 5}
    result = fallback_analysis(patterns, severity)
    # 21/78 = 27% error rate → below 30% threshold → DEGRADED (not UNHEALTHY)
    assert "DEGRADED" in result
    assert "Primary issue" in result
    assert "85%" in result


# --- analyse() dispatcher ---

def test_analyse_without_ai_calls_fallback():
    result = analyse(Counter({"disk error": 5}), {"CRITICAL": 0, "ERROR": 5, "WARNING": 0, "UNKNOWN": 0})
    assert isinstance(result, str)
    assert len(result) > 0

def test_analyse_with_ai_falls_back_on_error():
    # use_ai=True but stub raises NotImplementedError — should fall back silently
    result = analyse(
        Counter({"disk error": 5}),
        {"CRITICAL": 0, "ERROR": 5, "WARNING": 0, "UNKNOWN": 0},
        use_ai=True,
    )
    assert isinstance(result, str)
    assert "No issues detected." not in result
