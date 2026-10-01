import pytest

from app.analysis.content import classify_content
from app.models.common import SiteStatus


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        (
            {"status_code": 200, "html": "<p>x</p>", "text": "Welcome to our store, browse products and offers " * 5},
            SiteStatus.ACTIVE,
        ),
        (
            {"status_code": 200, "html": "", "text": "This domain is for sale! Buy this domain today."},
            SiteStatus.PARKED,
        ),
        ({"status_code": 200, "html": "", "text": "Hello", "nameservers": ["ns1.sedoparking.com"]}, SiteStatus.PARKED),
        (
            {"status_code": 200, "html": '<script src="https://img.sedoparking.com/x.js"></script>', "text": "Hi"},
            SiteStatus.PARKED,
        ),
        (
            {"status_code": 200, "html": "", "text": "This account has been suspended. Contact your hosting provider."},
            SiteStatus.TAKEDOWN,
        ),
        (
            {
                "status_code": 200,
                "html": "",
                "text": "THIS DOMAIN HAS BEEN SEIZED by the Federal Bureau of Investigation",
            },
            SiteStatus.TAKEDOWN,
        ),
        ({"status_code": 302, "html": '<a href="/cgi-sys/suspendedpage.cgi">', "text": ""}, SiteStatus.TAKEDOWN),
        ({"status_code": 200, "html": "", "text": "ok", "registry_status": ["clientHold"]}, SiteStatus.TAKEDOWN),
        (
            {"status_code": 200, "html": "", "text": "Phishing site has been removed for violating our terms"},
            SiteStatus.TAKEDOWN,
        ),
        ({"status_code": 404, "html": "", "text": "Not Found"}, SiteStatus.INACTIVE),
        ({"status_code": 200, "html": "", "text": "Oops! 404 - Page not found"}, SiteStatus.INACTIVE),
        (
            {"status_code": 200, "html": "", "text": "Welcome to nginx! If you see this page the server works"},
            SiteStatus.INACTIVE,
        ),
        ({"status_code": None, "html": None, "fetch_error": "request failed: Connection refused"}, SiteStatus.INACTIVE),
        ({"status_code": None, "html": None, "dns_resolves": False}, SiteStatus.INACTIVE),
        ({"status_code": None, "html": None, "fetch_error": "request failed: SSL handshake failure"}, SiteStatus.ERROR),
        ({"status_code": 503, "html": "<p>x</p>", "text": "Service Unavailable"}, SiteStatus.ERROR),
        ({"status_code": 451, "html": "", "text": "Unavailable"}, SiteStatus.TAKEDOWN),
    ],
)
def test_classification(kwargs, expected):
    verdict = classify_content(**kwargs)
    assert verdict.status == expected, verdict.to_dict()
    assert 0 < verdict.confidence <= 99
    assert verdict.reasons


def test_login_form_overrides_noise_words():
    verdict = classify_content(
        status_code=200, html="<form>", text="Coming soon - sign in to your account", has_login_form=True
    )
    assert verdict.status == SiteStatus.ACTIVE
    assert "live credential form" in verdict.reasons


def test_parking_nameserver_without_web():
    verdict = classify_content(status_code=None, html=None, fetch_error="timed out", nameservers=["ns2.bodis.com"])
    assert verdict.status == SiteStatus.PARKED
