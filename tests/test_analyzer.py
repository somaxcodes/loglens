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

def test_classify_severity_unknown():
    # "timeout" has no severity label — should not default to WARNING
    assert classify_severity("connection timeout after 30s") == "UNKNOWN"

def test_classify_severity_unknown_denied():
    assert classify_severity("permission denied for root") == "UNKNOWN"

def test_classify_severity_critical_takes_priority():
    assert classify_severity("critical error occurred") == "CRITICAL"


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
        "connection timeout",
    ]
    result = severity_breakdown(lines)
    assert result["CRITICAL"] == 1
    assert result["ERROR"] == 1
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
