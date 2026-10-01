"""Offline tests for provider response parsing."""

from app.models.graph import RelationType
from app.providers.credit.urlscan import parse_results
from app.providers.free.crtsh import parse_crtsh
from app.providers.free.cymru import hosting_name, origin_query_name, parse_asname, parse_origin
from app.providers.free.rdap import parse_entities
from app.providers.free.whois import parse_whois

CRT_ENTRIES = [
    {
        "id": 1,
        "issuer_name": 'C=US, O="Let\'s Encrypt", CN=R3',
        "common_name": "example.com",
        "name_value": "example.com\nwww.example.com\n*.mail.example.com",
        "not_before": "2026-01-01T00:00:00",
        "not_after": "2026-04-01T00:00:00",
        "serial_number": "abc",
    },
    {
        "id": 2,
        "issuer_name": "C=US, O=DigiCert Inc, CN=DigiCert",
        "common_name": "example.com",
        "name_value": "example.com\nexample-login.net",
        "not_before": "2026-05-01T00:00:00",
        "not_after": "2026-08-01T00:00:00",
        "serial_number": "def",
    },
]


def test_parse_crtsh_classifies_subdomains_and_cohosted_names():
    summary, related = parse_crtsh(CRT_ENTRIES, "example.com")
    assert summary["certificate_count"] == 2
    assert "www.example.com" in summary["subdomains"]
    assert "mail.example.com" in summary["subdomains"]
    assert summary["co_hosted_names"] == ["example-login.net"]
    rel = {r.value: r for r in related}
    assert "example.com" not in rel
    assert rel["www.example.com"].relation == RelationType.SUBDOMAIN_OF and rel["www.example.com"].reverse
    assert rel["example-login.net"].relation == RelationType.SHARES_CERTIFICATE
    assert summary["last_seen"] == "2026-05-01T00:00:00"
    assert summary["top_issuers"][0][1] == 1


def test_cymru_parsing():
    assert origin_query_name("1.2.3.4") == "4.3.2.1.origin.asn.cymru.com"
    assert origin_query_name("2001:db8::1").endswith(".origin6.asn.cymru.com")
    origin = parse_origin('"13335 | 104.16.0.0/13 | US | arin | 2014-03-28"')
    assert origin == {
        "asn": "13335",
        "prefix": "104.16.0.0/13",
        "country": "US",
        "registry": "arin",
        "allocated": "2014-03-28",
    }
    name = parse_asname('"13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US"')
    assert name == "CLOUDFLARENET - Cloudflare, Inc., US"
    assert hosting_name(name) == "Cloudflare, Inc."
    assert hosting_name("AMAZON-02, US") == "AMAZON-02"
    assert hosting_name(None) is None


def test_whois_parsing():
    text = """
Domain Name: EXAMPLE.COM
Registrar: RESERVED-Internet Assigned Numbers Authority
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2027-08-13T04:00:00Z
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Registrant Organization: REDACTED FOR PRIVACY
"""
    parsed = parse_whois(text)
    assert parsed["registrar"].startswith("RESERVED")
    assert parsed["created"] == "1995-08-14T04:00:00Z"
    assert parsed["expires"] == "2027-08-13T04:00:00Z"
    assert parsed["nameservers"] == ["a.iana-servers.net", "b.iana-servers.net"]
    assert "registrant_org" not in parsed  # redacted values are dropped
    assert parsed["privacy_protected"] is True
    assert parsed["status"] == ["clientDeleteProhibited"]


def test_rdap_entity_parsing():
    data = {
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar LLC"]]],
                "publicIds": [{"type": "IANA Registrar ID", "identifier": "9999"}],
                "entities": [
                    {"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@registrar.test"]]]}
                ],
            },
            {"roles": ["registrant"], "vcardArray": ["vcard", [["org", {}, "text", "Evil Corp"]]]},
        ]
    }
    parsed = parse_entities(data)
    assert parsed["registrar"] == "Example Registrar LLC"
    assert parsed["registrar_iana_id"] == "9999"
    assert parsed["abuse_email"] == "abuse@registrar.test"
    assert parsed["registrant_org"] == "Evil Corp"


def test_urlscan_parse_results():
    results = [
        {
            "_id": "u1",
            "task": {"time": "2026-01-01T00:00:00Z", "url": "https://a.test/"},
            "page": {
                "domain": "a.test",
                "ip": "203.0.113.5",
                "asn": "AS64500",
                "title": "Login",
                "url": "https://a.test/",
            },
            "screenshot": "https://urlscan.io/screenshots/u1.png",
        },
        {
            "_id": "u2",
            "task": {"time": "2026-02-01T00:00:00Z"},
            "page": {"domain": "b.test", "ip": "203.0.113.5", "asn": "AS64500", "title": "Login"},
        },
    ]
    summary, related = parse_results(results, RelationType.OBSERVED_WITH)
    assert summary["scan_count"] == 2
    assert summary["distinct_ips"] == ["203.0.113.5"]
    assert summary["last_scan"] == "2026-02-01T00:00:00Z"
    assert len(summary["historical_screenshots"]) == 1
    values = {(r.type, r.value) for r in related}
    assert ("domain", "a.test") in values and ("domain", "b.test") in values and ("ip", "203.0.113.5") in values
