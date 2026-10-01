import pytest

from app.models.common import IOCType
from app.utils.ioc import InvalidIOCError, is_public_ip, normalize_url, parse_ioc, refang, registered_domain


@pytest.mark.parametrize(
    ("raw", "expected_type", "expected_value"),
    [
        ("Example.COM", IOCType.DOMAIN, "example.com"),
        ("example.com.", IOCType.DOMAIN, "example.com"),
        ("*.example.com", IOCType.DOMAIN, "example.com"),
        ("https://Login.Example.com/Path?a=1#frag", IOCType.URL, "https://login.example.com/Path?a=1"),
        ("http://example.com:80/", IOCType.URL, "http://example.com/"),
        ("https://example.com:8443", IOCType.URL, "https://example.com:8443/"),
        ("8.8.8.8", IOCType.IP, "8.8.8.8"),
        ("2001:4860:4860::8888", IOCType.IP, "2001:4860:4860::8888"),
        ("hxxps://evil[.]example[.]com/login", IOCType.URL, "https://evil.example.com/login"),
        ("example.com/login", IOCType.URL, "http://example.com/login"),
        ("A" * 64, IOCType.CERTIFICATE, "a" * 64),
        ("AB:" * 19 + "AB", IOCType.CERTIFICATE, "ab" * 20),
        ("bücher.de", IOCType.DOMAIN, "xn--bcher-kva.de"),
    ],
)
def test_parse_ioc(raw, expected_type, expected_value):
    parsed = parse_ioc(raw)
    assert parsed.type == expected_type
    assert parsed.value == expected_value


def test_parse_ioc_sets_fetch_url():
    assert parse_ioc("example.com").url == "https://example.com/"
    assert parse_ioc("1.2.3.4").url == "http://1.2.3.4/"
    assert parse_ioc("2001:db8::1").url == "http://[2001:db8::1]/"
    assert parse_ioc("a" * 40).url is None


@pytest.mark.parametrize(
    "bad", ["", "   ", "not a domain", "ftp://example.com", "http://", "-bad-.com", "exa mple.com"]
)
def test_parse_ioc_rejects_invalid(bad):
    with pytest.raises(InvalidIOCError):
        parse_ioc(bad)


def test_refang_variants():
    assert refang("hxxp://a(.)b[dot]c") == "http://a.b.c"
    assert refang(" 'example[.]com' ") == "example.com"


def test_registered_domain_uses_public_suffix():
    assert registered_domain("login.secure.example.co.uk") == "example.co.uk"
    assert registered_domain("a.b.example.com") == "example.com"


def test_is_public_ip():
    assert is_public_ip("8.8.8.8")
    assert not is_public_ip("10.0.0.1")
    assert not is_public_ip("127.0.0.1")
    assert not is_public_ip("not-ip")


def test_normalize_url_requires_host():
    with pytest.raises(InvalidIOCError):
        normalize_url("https:///path")
