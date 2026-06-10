import re
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from redactor import redact_line, redact_lines


# --- redact_line ---

def test_redact_ip():
    result, counts = redact_line("connected from 192.168.1.100")
    assert "[REDACTED:IP]" in result
    assert counts.get("IP") == 1

def test_redact_email():
    result, counts = redact_line("sent to user@example.com")
    assert "[REDACTED:EMAIL]" in result
    assert counts.get("EMAIL") == 1

def test_redact_userid_uid():
    result, counts = redact_line("process uid=1000(john) attempted access")
    assert "[REDACTED:USERID]" in result
    assert counts.get("USERID") == 1

def test_redact_userid_user():
    result, counts = redact_line("login user=admin rejected")
    assert "[REDACTED:USERID]" in result

def test_redact_phone():
    result, counts = redact_line("call 555-867-5309 for support")
    assert "[REDACTED:PHONE]" in result
    assert counts.get("PHONE") == 1

def test_redact_multiple_types():
    line = "user@example.com logged in from 10.0.0.1"
    result, counts = redact_line(line)
    assert "[REDACTED:IP]" in result
    assert "[REDACTED:EMAIL]" in result
    assert len(counts) == 2

def test_redact_clean_line_unchanged():
    line = "system started normally at boot"
    result, counts = redact_line(line)
    assert result == line
    assert counts == {}

def test_redact_multiple_ips():
    line = "route from 10.0.0.1 to 10.0.0.2"
    result, counts = redact_line(line)
    assert counts.get("IP") == 2


# --- redact_lines ---

def test_redact_lines_totals():
    lines = [
        "error from 192.168.1.1",
        "sent email to user@example.com",
        "clean line with no pii",
    ]
    redacted, totals, changed = redact_lines(lines)
    assert totals.get("IP") == 1
    assert totals.get("EMAIL") == 1
    assert len(changed) == 2  # only the first two lines changed

def test_redact_lines_changed_pairs():
    lines = ["no pii here", "call 555-867-5309"]
    _, _, changed = redact_lines(lines)
    assert len(changed) == 1
    assert changed[0][0] == "call 555-867-5309"
    assert "[REDACTED:PHONE]" in changed[0][1]

def test_redact_lines_output_length():
    lines = ["line one", "line two", "error from 1.2.3.4"]
    redacted, _, _ = redact_lines(lines)
    assert len(redacted) == 3

def test_redact_lines_extra_patterns():
    custom = {"SSN": re.compile(r'\b\d{3}-\d{2}-\d{4}\b')}
    lines = ["ssn: 123-45-6789 on file"]
    redacted, totals, changed = redact_lines(lines, extra_patterns=custom)
    assert "[REDACTED:SSN]" in redacted[0]
    assert totals.get("SSN") == 1

def test_redact_lines_extra_patterns_no_overlap_with_builtin():
    # built-in patterns still work when extra_patterns is provided
    custom = {"SSN": re.compile(r'\b\d{3}-\d{2}-\d{4}\b')}
    lines = ["ip 192.168.1.1 and ssn 123-45-6789"]
    redacted, totals, _ = redact_lines(lines, extra_patterns=custom)
    assert "[REDACTED:IP]" in redacted[0]
    assert "[REDACTED:SSN]" in redacted[0]
