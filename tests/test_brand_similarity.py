from phishing_checker.analyzer import analyze


def test_official_paypal_domain_is_not_flagged():
    report = analyze(
        "https://paypal.com",
        fetch_dns=False,
        fetch_http=False,
    )

    assert not any(
        evidence.code == "BRAND_SIMILARITY"
        for evidence in report.evidence
    )


def test_official_brand_subdomain_is_not_flagged():
    report = analyze(
        "https://www.paypal.com",
        fetch_dns=False,
        fetch_http=False,
    )

    assert not any(
        evidence.code == "BRAND_SIMILARITY"
        for evidence in report.evidence
    )


def test_paypal_leet_is_flagged():
    report = analyze(
        "https://paypa1.com",
        fetch_dns=False,
        fetch_http=False,
    )

    evidence = [
        item
        for item in report.evidence
        if item.code == "BRAND_SIMILARITY"
    ]

    assert evidence
    assert evidence[0].details["brand"] == "paypal"


def test_microsoft_leet_is_flagged():
    report = analyze(
        "https://micros0ft.com",
        fetch_dns=False,
        fetch_http=False,
    )

    assert any(
        evidence.code == "BRAND_SIMILARITY"
        and evidence.details["brand"] == "microsoft"
        for evidence in report.evidence
    )


def test_google_domain_is_not_flagged():
    report = analyze(
        "https://google.com",
        fetch_dns=False,
        fetch_http=False,
    )

    assert not any(
        evidence.code == "BRAND_SIMILARITY"
        for evidence in report.evidence
    )


def test_leet_google_is_flagged():
    report = analyze(
        "https://g00gle.com",
        fetch_dns=False,
        fetch_http=False,
    )

    assert any(
        evidence.code == "BRAND_SIMILARITY"
        and evidence.details["brand"] == "google"
        for evidence in report.evidence
    )
