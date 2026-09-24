import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from collections import Counter
from ai_analysis import (
    fallback_analysis, analyse, _health_label, _build_prompt, run_ai_analysis,
    _shorten_keep_tag_whole, shorten,
)
import ai_analysis  # imported as a module too, so tests can monkeypatch ai_analysis.Groq directly


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

def test_analyse_with_ai_falls_back_on_error(monkeypatch):
    """
    Regression test: before this fix, this test called analyse(use_ai=True) with
    nothing mocked. That was fine back when run_ai_analysis() was a stub that
    always raised NotImplementedError — but now that run_ai_analysis() is real,
    the same test would have gone on to build a genuine Groq client and make a
    real network call using whatever GROQ_API_KEY happened to be set, on every
    test run. A test suite must not depend on network access or spend API quota.

    Fix: replace run_ai_analysis() itself with a fake that always raises,
    simulating any real failure (bad key, network down, Groq outage) without
    ever reaching the network. This isolates what we're actually testing here —
    that analyse()'s try/except falls back to fallback_analysis() — from whether
    run_ai_analysis() itself works, which is a separate concern already covered
    by test_build_prompt_redacts_pii_across_truncation_boundary and
    test_run_ai_analysis_never_sends_raw_pii above.
    """
    def _always_fails(*args, **kwargs):
        raise RuntimeError("simulated Groq failure — network down, bad key, etc.")

    monkeypatch.setattr(ai_analysis, "run_ai_analysis", _always_fails)

    result = analyse(
        Counter({"disk error": 5}),
        {"CRITICAL": 0, "ERROR": 5, "WARNING": 0, "UNKNOWN": 0},
        use_ai=True,
    )
    assert isinstance(result, str)
    assert "No issues detected." not in result
    assert "disk error" in result  # confirms it's fallback_analysis's real output, not an empty string


# --- _build_prompt PII redaction ---

def test_build_prompt_redacts_pii_across_truncation_boundary():
    """
    Regression test for a real bug found 2026-09-21: _build_prompt() used to call
    shorten() BEFORE redact_line(), so a PII match sitting near shorten()'s 160-char
    cutoff could be sliced in half by truncation and no longer match the redaction
    regex — a half email like "soma.das@exampl" doesn't match a full-email pattern,
    so it slipped through untouched.

    120 characters of filler is one of the lengths proven to leak before the fix
    (found by sweeping filler lengths 0-220 and checking every one for a leaked
    fragment of the email).
    """
    email = "soma.das@example.com"
    filler = "x" * 120
    pattern = f"sshd auth failure {filler} from {email} during pre-auth phase now"

    prompt = _build_prompt(
        Counter({pattern: 3}),
        {"CRITICAL": 0, "ERROR": 3, "WARNING": 0, "UNKNOWN": 0},
    )

    assert email not in prompt
    assert "soma.das@" not in prompt  # guards against a partial leak, not just the full address
    # Full tag, closing bracket included: _build_prompt() now truncates with
    # _shorten_keep_tag_whole(), which never cuts through a placeholder — see
    # test_shorten_keep_tag_whole_does_not_split_a_redaction_tag() below.
    assert "[REDACTED:EMAIL]" in prompt


# --- _shorten_keep_tag_whole: a redaction tag is never cut in half ---

def test_shorten_keep_tag_whole_does_not_split_a_redaction_tag():
    """
    Direct test of the tag-preserving rule, isolated from _build_prompt(). The
    tag "[REDACTED:EMAIL]" sits at indices 11-27 in this text. A plain shorten()
    at width=20 would cut at index 19 — squarely inside the tag, producing the
    mangled "[REDACTED:EMAI…". This asserts the cut is pushed past the tag
    instead, even though that means the result is longer than width=20.
    """
    text = "before tag [REDACTED:EMAIL] after this point continues on and on"
    width = 20

    result = _shorten_keep_tag_whole(text, width)

    assert "[REDACTED:EMAIL]" in result  # whole tag, closing bracket included
    assert result.endswith("…")
    assert len(result) > width  # proves it went past the limit on purpose to avoid cutting

def test_shorten_keep_tag_whole_matches_plain_shorten_when_no_tag_at_boundary():
    # sanity check: with nothing to protect, behaves exactly like shorten()
    text = "x" * 200
    assert _shorten_keep_tag_whole(text, 160) == shorten(text, 160)

def test_shorten_keep_tag_whole_leaves_short_text_untouched():
    assert _shorten_keep_tag_whole("short line", 160) == "short line"


# --- run_ai_analysis PII guarantee (network mocked, no real API call) ---

def test_run_ai_analysis_never_sends_raw_pii(monkeypatch):
    """
    Proves the guarantee end-to-end: whatever run_ai_analysis() actually hands to
    Groq contains no raw PII, using patterns that carry a real IP and a real email.

    The Groq client is replaced with a fake that records the `messages` it was
    called with instead of making an HTTP request. That keeps this test free, fast,
    deterministic, and runnable with no network access and no real API key — it is
    testing our redaction logic, not Groq's servers.
    """
    captured = {}

    class _FakeMessage:
        content = "fake ai response"

    class _FakeChoice:
        message = _FakeMessage()

    class _FakeCompletions:
        def create(self, **kwargs):
            captured["kwargs"] = kwargs
            return type("FakeResponse", (), {"choices": [_FakeChoice()]})()

    class _FakeChat:
        completions = _FakeCompletions()

    class _FakeGroqClient:
        def __init__(self, api_key):
            self.chat = _FakeChat()

    monkeypatch.setenv("GROQ_API_KEY", "test-key-not-real")
    monkeypatch.setattr(ai_analysis, "Groq", _FakeGroqClient)

    patterns = Counter({
        "Failed password for root from 203.0.113.55 port 22 ssh2": 5,
        "authentication failure for soma.das@example.com": 3,
    })
    severity = {"CRITICAL": 0, "ERROR": 8, "WARNING": 0, "UNKNOWN": 0}
    services = {"sshd": [""] * 8}

    result = run_ai_analysis(patterns, severity, services)

    sent_text = " ".join(m["content"] for m in captured["kwargs"]["messages"])
    assert "203.0.113.55" not in sent_text
    assert "soma.das@example.com" not in sent_text
    assert result == "fake ai response"  # confirms the fake was actually used, not a real call
