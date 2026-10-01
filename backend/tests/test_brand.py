from app.analysis.brand import assess_brand, brand_tokens, infer_brand, skeleton
from app.fingerprints.images import image_fingerprints
from app.fingerprints.website import extract_website_fingerprints
from tests.helpers import PHISH_HTML, png_bytes

FP = extract_website_fingerprints(PHISH_HTML, "https://contoso-secure-login.test/verify")


def test_skeleton_and_tokens():
    assert skeleton("paypa1") == "paypal"
    assert skeleton("rnicrosoft") == "microsoft"
    assert skeleton("xn--pypal-4ve") == "paypal"  # Cyrillic 'а'
    assert brand_tokens("The Contoso Bank Inc") == ["contoso", "bank"]


def test_infer_brand_from_title_and_meta():
    assert infer_brand(FP) == "Contoso Bank"
    assert infer_brand({"meta": {"og:site_name": "Fabrikam"}}) == "Fabrikam"
    assert infer_brand({"title": "Home"}) is None


def test_phishing_page_on_lookalike_domain_scores_high():
    logo = image_fingerprints(png_bytes())["phash"]
    a = assess_brand(
        "contoso-secure-login.test",
        FP,
        brand="Contoso",
        brand_domains=["contoso.com"],
        brand_logo_hashes=[logo],
        page_logo_hashes=[logo],
    )
    assert a.legitimate is False
    assert a.signals["brand_in_domain"] and a.signals["login_form"] and a.signals["credential_collection"]
    assert a.signals["logo_similarity"] == 1.0
    assert "secure" in a.signals["domain_keywords"] and "login" in a.signals["domain_keywords"]
    assert a.brand_similarity_score >= 80
    assert a.impersonation_score >= 80
    assert any("external host" in i for i in a.indicators)


def test_legitimate_brand_domain_is_zeroed():
    a = assess_brand("login.contoso.com", FP, brand="Contoso", brand_domains=["contoso.com"])
    assert a.legitimate and a.impersonation_score == 0
    assert a.brand_similarity_score > 0


def test_typosquat_and_homoglyph_detection():
    typo = assess_brand("cont0so.test", {"title": "Sign in"}, brand="Contoso")
    assert typo.signals.get("homoglyph") or typo.signals.get("typosquat")
    near = assess_brand("contosa.test", {"title": "Sign in"}, brand="Contoso", brand_domains=["contoso.com"])
    assert near.signals.get("typosquat") is True


def test_unrelated_site_without_brand_scores_low():
    fp = extract_website_fingerprints(
        "<html><head><title>Cooking recipes</title></head><body>Pasta and pizza recipes for every day</body></html>",
        "https://recipes.test/",
    )
    a = assess_brand("recipes.test", fp, brand="Contoso")
    assert a.brand_similarity_score == 0
    assert a.impersonation_score < 10


def test_inactive_site_dampens_score():
    active = assess_brand("contoso-verify.test", FP, brand="Contoso")
    parked = assess_brand("contoso-verify.test", FP, brand="Contoso", site_active=False)
    assert parked.impersonation_score < active.impersonation_score
