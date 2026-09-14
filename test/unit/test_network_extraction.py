"""Pure extraction tests -- network/crypto/C2-channel categories. No execution, no
AL framework, no real/live malicious IOCs.

Important Magpie-specific wrinkle: Python's `ipaddress` module classifies RFC
5737 (192.0.2.0/24 etc.) and RFC 3849 (2001:db8::/32) documentation-range
addresses as `is_private` (IANA special-purpose), and Magpie's own
_is_private_or_loopback() filter correctly excludes them from extract_ips()'s
output. So the usual "always use documentation-range placeholders" convention
can't be used for a test asserting "this IP is surfaced as suspicious" -- doing
so would just prove the (correct) private-address filter works, not that public
IPs get through. Those tests instead use a well-known, benign, non-malicious
public address (8.8.8.8 / 2001:4860:4860::8888, a public DNS resolver) purely to
exercise the public/private boundary -- do NOT "fix" these back to
documentation-range addresses, that would silently break the test's purpose.
Regex/candidate-*correctness* tests (is the match truncated or not) are
independent of this and freely use 2001:db8::-style documentation addresses,
since they test the regex, not the filtering policy.
"""
from magpie.extraction import (
    _iter_ipv6_candidates,
    extract_c2_channels,
    extract_cloud_meta,
    extract_emails,
    extract_ips,
    extract_onions,
    extract_stratum,
    extract_user_agents,
    extract_wallets,
)


# ---------------------------------------------------------------------------
# IPv6 regex correctness (the actual bug fix) -- candidate layer only
# ---------------------------------------------------------------------------

def test_ipv6_compressed_middle_not_truncated():
    candidates = list(_iter_ipv6_candidates(b"c2 host 2001:db8::1 port"))
    assert ("2001:db8::1", "") in candidates


def test_ipv6_bracketed_with_port_not_truncated():
    candidates = list(_iter_ipv6_candidates(b"[2001:db8::1]:8080"))
    assert ("2001:db8::1", "8080") in candidates


def test_ipv6_unbracketed_trailing_number_does_not_leak_into_port():
    candidates = list(_iter_ipv6_candidates(b"2001:db8::1 8080"))
    ips = [c for c in candidates if c[0] == "2001:db8::1"]
    assert ips and ips[0][1] == ""


def test_ipv6_full_uncompressed_form():
    candidates = list(_iter_ipv6_candidates(b"2001:0db8:0000:0000:0000:0000:0000:0001"))
    assert ("2001:db8::1", "") in candidates


def test_ipv6_degenerate_fragment_rejected():
    candidates = list(_iter_ipv6_candidates(b"noise a:: more noise"))
    assert candidates == []


# ---------------------------------------------------------------------------
# Public/private classification -- full extract_ips()
# ---------------------------------------------------------------------------

def test_ipv6_loopback_excluded():
    ips = extract_ips(b"::1")
    assert ips == []


def test_ipv6_link_local_excluded():
    ips = extract_ips(b"fe80::1")
    assert ips == []


def test_ipv6_unique_local_excluded():
    ips = extract_ips(b"fc00::1")
    assert ips == []


def test_ipv6_public_address_surfaced_with_suspicious_port():
    # 2001:4860:4860::8888 is a well-known PUBLIC DNS resolver address (Google) --
    # explicitly NOT an IOC, used only because RFC 3849's documentation range
    # (2001:db8::/32) is itself classified is_private and can't exercise this path.
    ips = extract_ips(b"c2: [2001:4860:4860::8888]:3333")
    matches = [i for i in ips if i[0] == "2001:4860:4860::8888"]
    assert matches
    ip, port, suspicious = matches[0]
    assert port == "3333"
    assert suspicious is True


def test_ipv4_documentation_range_excluded():
    for ip in (b"192.0.2.10", b"198.51.100.20", b"203.0.113.5"):
        assert extract_ips(ip) == []


def test_ipv4_public_address_surfaced_with_suspicious_port():
    # 8.8.8.8 is a well-known PUBLIC benign address (Google DNS), not an IOC --
    # used only to exercise the public-address code path.
    ips = extract_ips(b"8.8.8.8:4444")
    assert ips == [("8.8.8.8", "4444", True)]


def test_ipv4_public_address_without_mining_port_not_suspicious():
    ips = extract_ips(b"8.8.8.8:80")
    assert ips == [("8.8.8.8", "80", False)]


# ---------------------------------------------------------------------------
# Existing categories -- regression (placeholder, unfunded/non-real addresses)
# ---------------------------------------------------------------------------

def test_btc_wallet_extracted():
    placeholder = "1" + "A" * 33  # valid base58 charset, clearly not a real funded address
    wallets = extract_wallets(placeholder.encode())
    assert ("BTC", placeholder) in wallets


def test_eth_wallet_extracted():
    placeholder = "0x" + "f" * 40
    wallets = extract_wallets(placeholder.encode())
    assert ("ETH", placeholder) in wallets


def test_xmr_wallet_extracted():
    placeholder = "4" + "0" + "A" * 93
    wallets = extract_wallets(placeholder.encode())
    assert ("XMR", placeholder) in wallets


def test_stratum_connection_extracted():
    val = "stratum+tcp://placeholder-pool.example:3333"
    assert extract_stratum(val.encode()) == [val]


def test_onion_v3_extracted():
    val = "a" * 56 + ".onion"
    assert extract_onions(val.encode()) == [val]


def test_onion_v2_extracted():
    val = "a" * 16 + ".onion"
    assert extract_onions(val.encode()) == [val]


def test_email_extracted():
    assert extract_emails(b"contact: person@example.com") == ["person@example.com"]


def test_cloud_metadata_access_detected():
    val = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    assert extract_cloud_meta(val.encode()) == [val]


# ---------------------------------------------------------------------------
# New: modern C2/exfil channels
# ---------------------------------------------------------------------------

def test_discord_webhook_extracted():
    val = "https://discord.com/api/webhooks/123456789012345678/" + "A" * 70
    channels = extract_c2_channels(val.encode())
    assert val in channels.get("discord_webhook", [])


def test_telegram_bot_url_extracted():
    val = "https://api.telegram.org/bot123456789:" + "A" * 35
    channels = extract_c2_channels(val.encode())
    assert val in channels.get("telegram_bot", [])


def test_telegram_bare_token_not_double_counted_inside_url_match():
    val = "https://api.telegram.org/bot123456789:" + "A" * 35
    channels = extract_c2_channels(val.encode())
    # only one telegram_bot entry, not two (URL match + bare-token match of the
    # same substring)
    assert len(channels.get("telegram_bot", [])) == 1


def test_telegram_bare_token_extracted_standalone():
    val = "leaked token: 123456789:" + "A" * 35
    channels = extract_c2_channels(val.encode())
    assert any("123456789:" + "A" * 35 == v for v in channels.get("telegram_bot", []))


def test_pastebin_raw_extracted():
    val = "https://pastebin.com/raw/AbCdEf12"
    channels = extract_c2_channels(val.encode())
    assert val in channels.get("pastebin_raw", [])


def test_no_c2_channels_on_benign_text():
    assert extract_c2_channels(b"hello world, nothing to see here") == {}


# ---------------------------------------------------------------------------
# New: User-Agent strings
# ---------------------------------------------------------------------------

def test_user_agent_mozilla_form_extracted():
    val = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) placeholder-agent/1.0"
    assert val in extract_user_agents(val.encode())


def test_user_agent_header_form_extracted():
    uas = extract_user_agents(b"User-Agent: PlaceholderBot/1.0\r\n")
    assert "PlaceholderBot/1.0" in uas
