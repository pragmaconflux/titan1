"""Enrichment engine for geo/WHOIS/YARA lookups.

Optional enrichment for IOCs. All enrichment is opt-in via config and gracefully
degrades if dependencies are missing or services are unavailable.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)


class EnrichmentEngine:
    """Handles optional geo/WHOIS/YARA enrichment."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enable_geo = config.get("enable_geo_enrichment", False)
        self.enable_whois = config.get("enable_whois", False)
        self.enable_yara = config.get("enable_yara", False)
        self.geo_db_path = config.get("geo_db_path")
        self.yara_rules_path = config.get("yara_rules_path")

        self.geo_reader = None
        self.whois_available = False
        self.yara_rules = None

        # Rate limiting
        self.whois_cache: Dict[str, Any] = {}
        self.whois_cooldown = 2.0  # seconds between queries
        self.last_whois_query = 0.0

        self._init_geo()
        self._init_whois()
        self._init_yara()

    def _init_geo(self):
        """Initialize GeoIP reader if available."""
        if not self.enable_geo:
            return

        try:
            import geoip2.database

            if self.geo_db_path and Path(self.geo_db_path).exists():
                self.geo_reader = geoip2.database.Reader(self.geo_db_path)
                logger.info("GeoIP database loaded")
            else:
                logger.warning("GeoIP enabled but database not found")
        except ImportError:
            logger.warning("GeoIP enabled but geoip2 library not installed")
        except Exception as e:
            logger.error(f"Failed to load GeoIP database: {e}")

    def _init_whois(self):
        """Check if WHOIS is available."""
        if not self.enable_whois:
            return

        try:
            import whois  # noqa: F401

            self.whois_available = True
            logger.info("WHOIS enrichment available")
        except ImportError:
            logger.warning("WHOIS enabled but python-whois library not installed")

    def _init_yara(self):
        """Load YARA rules if available."""
        if not self.enable_yara:
            return

        try:
            import yara

            if self.yara_rules_path and Path(self.yara_rules_path).exists():
                self.yara_rules = yara.compile(filepath=self.yara_rules_path)
                logger.info("YARA rules loaded")
            else:
                logger.warning("YARA enabled but rules file not found")
        except ImportError:
            logger.warning("YARA enabled but yara-python library not installed")
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")

    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """Enrich an IP address with geo/WHOIS data."""
        result: Dict[str, Any] = {"ip": ip}

        # Geo lookup
        if self.geo_reader:
            try:
                response = self.geo_reader.city(ip)
                result["geo"] = {
                    "country": response.country.name,
                    "country_code": response.country.iso_code,
                    "city": response.city.name,
                    "latitude": response.location.latitude,
                    "longitude": response.location.longitude,
                }
            except Exception as e:
                logger.debug(f"GeoIP lookup failed for {ip}: {e}")
                result["geo"] = None

        # WHOIS lookup with rate limiting
        if self.whois_available:
            if ip in self.whois_cache:
                result["whois"] = self.whois_cache[ip]
            else:
                now = time.time()
                if now - self.last_whois_query >= self.whois_cooldown:
                    try:
                        import whois as whois_lib

                        self.last_whois_query = now
                        whois_data = whois_lib.whois(ip)
                        result["whois"] = {
                            "org": getattr(whois_data, "org", None),
                            "registrar": getattr(whois_data, "registrar", None),
                            "country": getattr(whois_data, "country", None),
                        }
                        self.whois_cache[ip] = result["whois"]
                    except Exception as e:
                        logger.debug(f"WHOIS lookup failed for {ip}: {e}")
                        result["whois"] = None
                else:
                    result["whois"] = {"_rate_limited": True}

        return result

    def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """Enrich a domain with WHOIS data."""
        result: Dict[str, Any] = {"domain": domain}

        if self.whois_available:
            if domain in self.whois_cache:
                result["whois"] = self.whois_cache[domain]
            else:
                now = time.time()
                if now - self.last_whois_query >= self.whois_cooldown:
                    try:
                        import whois as whois_lib

                        self.last_whois_query = now
                        whois_data = whois_lib.whois(domain)
                        result["whois"] = {
                            "registrar": getattr(whois_data, "registrar", None),
                            "creation_date": str(
                                getattr(whois_data, "creation_date", None)
                            ),
                            "expiration_date": str(
                                getattr(whois_data, "expiration_date", None)
                            ),
                            "name_servers": getattr(whois_data, "name_servers", []),
                        }
                        self.whois_cache[domain] = result["whois"]
                    except Exception as e:
                        logger.debug(f"WHOIS lookup failed for {domain}: {e}")
                        result["whois"] = None
                else:
                    result["whois"] = {"_rate_limited": True}

        return result

    def scan_with_yara(
        self, data: bytes, label: str = "sample"
    ) -> List[Dict[str, Any]]:
        """Scan data with YARA rules."""
        matches = []

        if not self.yara_rules:
            return matches

        try:
            yara_matches = self.yara_rules.match(data=data)
            for match in yara_matches:
                matches.append(
                    {
                        "rule": match.rule,
                        "tags": match.tags,
                        "meta": match.meta,
                        "label": label,
                    }
                )
        except Exception as e:
            logger.error(f"YARA scan failed: {e}")

        return matches

    def enrich_iocs(self, iocs: Dict[str, List[str]]) -> Dict[str, Any]:
        """Enrich all IOCs in a batch."""
        enriched: Dict[str, Any] = {
            "ips": [],
            "domains": [],
        }

        # Enrich public IPs only
        for ip in iocs.get("ipv4_public", [])[:10]:  # Limit to 10 to avoid rate limits
            enriched["ips"].append(self.enrich_ip(ip))

        # Enrich domains
        for domain in iocs.get("domains", [])[:10]:  # Limit to 10
            enriched["domains"].append(self.enrich_domain(domain))

        return enriched

    def cleanup(self):
        """Clean up resources."""
        if self.geo_reader:
            try:
                self.geo_reader.close()
            except Exception:
                pass
