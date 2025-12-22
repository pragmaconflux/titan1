from __future__ import annotations

from pathlib import Path

from titan_decoder.core.enrichment import EnrichmentEngine
from titan_decoder.core.enrichment_cache import EnrichmentCache


def test_enrichment_cache_get_set_roundtrip(tmp_path: Path):
    db = tmp_path / "cache.db"
    cache = EnrichmentCache(db)

    assert cache.get("whois", "domain", "example.com") is None

    cached_at = cache.set(
        "whois",
        "domain",
        "example.com",
        {"whois": {"registrar": "X", "creation_date": "2020-01-01"}},
    )
    hit = cache.get("whois", "domain", "example.com")
    assert hit is not None
    assert hit.cached_at == cached_at
    assert hit.payload["whois"]["registrar"] == "X"


class _GeoReaderStub:
    def __init__(self):
        self.calls = 0

    def city(self, ip: str):
        self.calls += 1

        class _Country:
            name = "United States"
            iso_code = "US"

        class _City:
            name = "Seattle"

        class _Location:
            latitude = 47.6062
            longitude = -122.3321

        class _Resp:
            country = _Country()
            city = _City()
            location = _Location()

        return _Resp()


def test_enrichment_engine_geo_uses_cache_by_default(tmp_path: Path):
    cfg = {
        "enable_geo_enrichment": True,
        "geo_db_path": None,
        "enable_whois": False,
        "enable_yara": False,
        "enable_enrichment_cache": True,
        "enrichment_cache_path": str(tmp_path / "enrichment_cache.db"),
        "refresh_enrichment": False,
    }

    engine = EnrichmentEngine(cfg)
    engine.geo_reader = _GeoReaderStub()

    r1 = engine.enrich_ip("8.8.8.8")
    r2 = engine.enrich_ip("8.8.8.8")

    assert engine.geo_reader.calls == 1
    assert r1["geo"]["country_code"] == "US"
    assert r2["geo"]["country_code"] == "US"


def test_enrichment_engine_refresh_bypasses_cache(tmp_path: Path):
    cfg = {
        "enable_geo_enrichment": True,
        "geo_db_path": None,
        "enable_whois": False,
        "enable_yara": False,
        "enable_enrichment_cache": True,
        "enrichment_cache_path": str(tmp_path / "enrichment_cache.db"),
        "refresh_enrichment": True,
    }

    engine = EnrichmentEngine(cfg)
    engine.geo_reader = _GeoReaderStub()

    engine.enrich_ip("8.8.8.8")
    engine.enrich_ip("8.8.8.8")

    assert engine.geo_reader.calls == 2
