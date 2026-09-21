import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from analyzer import (
    filter_issues,
    classify_severity,
    parse_syslog_line,
    normalize_message,
    severity_breakdown,
    group_by_service,
)

ISO_LINE   = "2026-05-28T15:47:10.452601+00:00 host kernel: something failed here"
TRAD_LINE  = "May 31 13:22:19 host sshd[123]: error reading config"
CLEAN_LINE = "2026-05-28T15:47:10.000000+00:00 host kernel: system started normally"


# --- filter_issues ---

def test_filter_issues_catches_error():
    assert filter_issues(["disk error detected"]) == [("disk error detected", "error")]

def test_filter_issues_catches_warning():
    assert filter_issues(["WARNING: low memory"]) == [("WARNING: low memory", "warning")]

def test_filter_issues_catches_critical():
    assert filter_issues(["CRITICAL failure"]) == [("CRITICAL failure", "critical")]

def test_filter_issues_catches_failed():
    assert filter_issues(["login failed"]) == [("login failed", "failed")]

def test_filter_issues_catches_failure():
    assert filter_issues(["connection failure"]) != []

def test_filter_issues_catches_exception():
    # "exception" must appear as a standalone word — compound class names don't match
    assert filter_issues(["uncaught exception in main thread"]) != []

def test_filter_issues_catches_fatal():
    assert filter_issues(["fatal: repository not found"]) != []

def test_filter_issues_catches_timeout():
    assert filter_issues(["connection timeout after 30s"]) != []

def test_filter_issues_catches_denied():
    assert filter_issues(["permission denied for user"]) != []

def test_filter_issues_catches_panic():
    assert filter_issues(["kernel panic - not syncing"]) != []

def test_filter_issues_blocks_clean_line():
    assert filter_issues(["system started normally"]) == []

def test_filter_issues_case_insensitive():
    assert filter_issues(["FAILED to mount volume"]) != []


# --- classify_severity ---

def test_classify_severity_critical():
    assert classify_severity("critical: disk failure") == "CRITICAL"

def test_classify_severity_error():
    assert classify_severity("error reading socket") == "ERROR"

def test_classify_severity_failed():
    assert classify_severity("login failed") == "ERROR"

def test_classify_severity_warning():
    assert classify_severity("WARNING low disk space") == "WARNING"

def test_classify_severity_inferred_error_timeout():
    # no explicit label, but a timeout IS a failed operation — must not land in UNKNOWN
    assert classify_severity("connection timeout after 30s") == "ERROR"

def test_classify_severity_inferred_error_denied():
    assert classify_severity("permission denied for root") == "ERROR"

def test_classify_severity_critical_takes_priority():
    assert classify_severity("critical error occurred") == "CRITICAL"

def test_classify_severity_fatal_is_critical():
    # regression: "PCI: Fatal: No config space access function found" used to report UNKNOWN
    assert classify_severity("PCI: Fatal: No config space access function found") == "CRITICAL"

def test_classify_severity_panic_is_critical():
    assert classify_severity("Kernel panic - not syncing: Attempted to kill init") == "CRITICAL"

def test_classify_severity_panic_boot_param_not_critical():
    # "panic=-1" is a boot policy setting, not a crash
    assert classify_severity("Kernel command line: BOOT_IMAGE=/vmlinuz panic=-1 quiet") != "CRITICAL"

def test_classify_severity_fatal_signal_is_critical():
    assert classify_severity("weston: potentially unexpected fatal signal 6.") == "CRITICAL"

def test_classify_severity_inferred_error_refused():
    assert classify_severity("connect to host failed: connection refused") == "ERROR"

def test_classify_severity_inferred_error_exception():
    assert classify_severity("Uncaught exception in worker thread") == "ERROR"

def test_classify_severity_inferred_error_abort():
    assert classify_severity("transaction aborted, rolling back") == "ERROR"

def test_every_issue_keyword_has_a_severity_tier():
    """Regression guard for the root cause: _ISSUE_PATTERN and classify_severity drifting apart."""
    for keyword in ("critical", "error", "failed", "failure", "warning", "exception",
                    "panic", "aborted", "denied", "timeout", "refused", "fatal"):
        assert classify_severity(f"service: {keyword} in operation") != "UNKNOWN", keyword

def test_classify_severity_explicit_warning_beats_inferred_error():
    # a service that labelled its own line WARNING must not be promoted to ERROR
    assert classify_severity("WARNING: connection refused, will retry") == "WARNING"


# --- parse_syslog_line ---

def test_parse_syslog_iso_format():
    result = parse_syslog_line(ISO_LINE)
    assert result is not None
    assert result["service"] == "kernel"
    assert result["hostname"] == "host"
    assert "failed" in result["message"]

def test_parse_syslog_traditional_format():
    result = parse_syslog_line(TRAD_LINE)
    assert result is not None
    assert result["service"] == "sshd"
    assert result["pid"] == "123"

def test_parse_syslog_returns_none_for_unknown():
    assert parse_syslog_line("this is not a syslog line at all") is None


# --- normalize_message ---

def test_normalize_ip():
    assert "<IP>" in normalize_message("connected to 192.168.1.1 successfully")

def test_normalize_port():
    assert "<PORT>" in normalize_message("listening on port 8080")

def test_normalize_hex():
    assert "<ADDR>" in normalize_message("address 0xdeadbeef")

def test_normalize_long_number():
    assert "<NUM>" in normalize_message("pid 123456 exited")

def test_normalize_short_number_unchanged():
    # numbers under 4 digits should not be replaced
    result = normalize_message("retry 3 times")
    assert "3" in result


# --- severity_breakdown ---

def test_severity_breakdown_counts():
    lines = [
        "critical failure",
        "disk error",
        "WARNING: low memory",
        "connection timeout",          # inferred ERROR
        "POSSIBLE BREAK-IN ATTEMPT!",  # no severity signal at all → UNKNOWN
    ]
    result = severity_breakdown(lines)
    assert result["CRITICAL"] == 1
    assert result["ERROR"] == 2
    assert result["WARNING"] == 1
    assert result["UNKNOWN"] == 1

def test_severity_breakdown_all_keys_present():
    result = severity_breakdown([])
    assert set(result.keys()) == {"CRITICAL", "ERROR", "WARNING", "UNKNOWN"}


# --- group_by_service ---

def test_group_by_service_known():
    lines = [ISO_LINE, TRAD_LINE]
    groups = group_by_service(lines)
    assert "kernel" in groups
    assert "sshd" in groups

def test_group_by_service_unknown_fallback():
    groups = group_by_service(["this line has no syslog format"])
    assert "unknown" in groups
