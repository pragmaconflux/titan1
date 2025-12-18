"""File hashing and optional AV intelligence lookups.

Adds MD5/SHA1/SHA256 hashing for all decoded artifacts with optional
VirusTotal or other AV service lookups (rate-limited, cached).
"""

from __future__ import annotations

import hashlib
import time
import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


class FileHasher:
    """Compute multiple hashes for a byte blob."""
    
    @staticmethod
    def hash_data(data: bytes) -> Dict[str, str]:
        """Compute MD5, SHA1, and SHA256 for data."""
        return {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }


class AVIntelligence:
    """Optional AV intelligence lookups (VirusTotal, etc.)."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.vt_api_key = config.get("virustotal_api_key")
        self.vt_enabled = bool(self.vt_api_key)
        self.vt_cache: Dict[str, Any] = {}
        self.vt_rate_limit = config.get("virustotal_rate_limit", 4)  # requests per minute
        self.vt_last_request = 0.0
        
        if self.vt_enabled:
            logger.info("VirusTotal lookups enabled")

    def lookup_virustotal(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Look up a hash on VirusTotal (rate-limited)."""
        if not self.vt_enabled:
            return None
        
        # Check cache
        if file_hash in self.vt_cache:
            return self.vt_cache[file_hash]
        
        # Rate limiting
        now = time.time()
        time_since_last = now - self.vt_last_request
        min_interval = 60.0 / self.vt_rate_limit
        
        if time_since_last < min_interval:
            logger.debug(f"VT rate limited, waiting {min_interval - time_since_last:.2f}s")
            return {"_rate_limited": True}
        
        try:
            import requests
            self.vt_last_request = now
            
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": self.vt_api_key}
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                result = {
                    "found": True,
                    "positives": data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0),
                    "total": sum(data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).values()),
                    "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
                }
                self.vt_cache[file_hash] = result
                return result
            elif response.status_code == 404:
                result = {"found": False}
                self.vt_cache[file_hash] = result
                return result
            else:
                logger.warning(f"VT lookup failed with status {response.status_code}")
                return None
        except ImportError:
            logger.warning("VT lookups enabled but requests library not installed")
            self.vt_enabled = False
            return None
        except Exception as e:
            logger.error(f"VT lookup error: {e}")
            return None

    def enrich_hashes(self, hashes: List[str]) -> Dict[str, Any]:
        """Enrich multiple hashes with AV intelligence."""
        results = {}
        for h in hashes[:5]:  # Limit to 5 to respect rate limits
            vt_result = self.lookup_virustotal(h)
            if vt_result:
                results[h] = {"virustotal": vt_result}
        return results
