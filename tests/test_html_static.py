"""Static HTML inspection tests; no JavaScript is executed."""

from phishing_checker.html import analyze_html


def test_password_form_creates_static_evidence() -> None:
    html = '<form action="https://evil.example/login"><input type="password"></form>'
    report = analyze_html(html, base_url="https://example.com/")
    codes = {item.code for item in report.evidence}
    assert "HTML_PASSWORD_INPUT" in codes
    assert "HTML_EXTERNAL_FORM" in codes


def test_javascript_is_not_executed() -> None:
    html = '<script>window.__executed = true</script><form><input type="password"></form>'
    report = analyze_html(html, base_url="https://example.com/")
    assert report.evidence
