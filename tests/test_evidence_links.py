def test_evidence_links_dns_client_to_domain_and_domain_to_answer_ip():
    from titan_decoder.core.evidence_links import build_links_from_evidence_events

    events = [
        {
            "event_type": "dns_query",
            "timestamp": "2025-01-01T00:00:01Z",
            "source": "dns.csv",
            "extracted_by": "evidence_parser:dns",
            "src_ip": "10.0.0.10",
            "domain": "example.com",
            "raw": {"answers": "93.184.216.34"},
        }
    ]

    links = build_links_from_evidence_events(events)
    keys = {
        (
            l["src"]["type"],
            l["src"]["value"],
            l["dst"]["type"],
            l["dst"]["value"],
            l["reason_code"],
        )
        for l in links
    }

    assert ("ipv4", "10.0.0.10", "domains", "example.com", "dns_client_queried_domain") in keys
    assert ("domains", "example.com", "ipv4", "93.184.216.34", "dns_answer") in keys


def test_evidence_links_dns_ignores_non_ip_answers():
    from titan_decoder.core.evidence_links import build_links_from_evidence_events

    events = [
        {
            "event_type": "dns_query",
            "timestamp": "2025-01-01T00:00:01Z",
            "source": "dns.csv",
            "extracted_by": "evidence_parser:dns",
            "src_ip": "10.0.0.10",
            "domain": "example.com",
            "raw": {"answers": ["not-an-ip", "93.184.216.34"]},
        }
    ]

    links = build_links_from_evidence_events(events)
    # Only one answer-based IP link should exist
    ip_links = [l for l in links if l.get("reason_code") == "dns_answer"]
    assert len(ip_links) == 1
    assert ip_links[0]["dst"]["value"] == "93.184.216.34"
