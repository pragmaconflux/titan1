"""Crypto key detection and Windows API call extraction."""

import re
from typing import List, Dict, Any, Optional


class CryptoKeyDetector:
    """Detect cryptographic keys in data."""

    # Common crypto key signatures
    CRYPTO_SIGNATURES = {
        'RSA_PRIVATE': b'-----BEGIN RSA PRIVATE KEY-----',
        'RSA_PUBLIC': b'-----BEGIN RSA PUBLIC KEY-----',
        'OPENSSH_PRIVATE': b'-----BEGIN OPENSSH PRIVATE KEY-----',
        'PGP_PRIVATE': b'-----BEGIN PGP PRIVATE KEY BLOCK-----',
        'CERTIFICATE': b'-----BEGIN CERTIFICATE-----',
        'PKCS8': b'-----BEGIN PRIVATE KEY-----',
    }

    @staticmethod
    def find_keys(data: bytes) -> List[Dict[str, Any]]:
        """Find cryptographic keys in data."""
        keys = []
        
        for key_type, signature in CryptoKeyDetector.CRYPTO_SIGNATURES.items():
            if signature in data:
                # Find the key block
                start = data.find(signature)
                # Estimate end (usually marked with -----END...)
                end_marker = b'-----END'
                end = data.find(end_marker, start)
                if end != -1:
                    end = data.find(b'-----', end + 1) + 5  # Include end marker
                    key_data = data[start:end]
                    
                    keys.append({
                        'type': key_type,
                        'offset': start,
                        'length': len(key_data),
                        'preview': key_data[:100] + b'...' if len(key_data) > 100 else key_data,
                    })

        # Detect hex-encoded keys (32+ hex chars in sequence)
        hex_keys = re.findall(b'[0-9a-fA-F]{64,}', data)
        for hex_key in hex_keys[:5]:  # Limit to top 5
            if len(hex_key) >= 64:  # At least 256-bit
                keys.append({
                    'type': f'Hex-encoded key ({len(hex_key)//2} bytes)',
                    'offset': data.find(hex_key),
                    'length': len(hex_key),
                    'preview': hex_key[:80],
                })

        return keys


class WindowsAPIExtractor:
    """Extract Windows API calls from executable code."""

    # Common Windows APIs used in malware
    SUSPICIOUS_APIS = {
        'CreateProcessA': 'process creation',
        'CreateProcessW': 'process creation',
        'ShellExecuteA': 'shell execution',
        'ShellExecuteW': 'shell execution',
        'WinExec': 'execute command',
        'CreateRemoteThread': 'code injection',
        'VirtualAllocEx': 'memory allocation (injection)',
        'WriteProcessMemory': 'write to process (injection)',
        'CreateFileA': 'file access',
        'CreateFileW': 'file access',
        'RegOpenKeyExA': 'registry access',
        'RegOpenKeyExW': 'registry access',
        'InternetOpenA': 'network connection',
        'InternetOpenW': 'network connection',
        'HttpOpenRequestA': 'HTTP request',
        'HttpOpenRequestW': 'HTTP request',
        'URLDownloadToFileA': 'file download',
        'URLDownloadToFileW': 'file download',
        'GetModuleHandleA': 'module loading',
        'GetModuleHandleW': 'module loading',
        'GetProcAddress': 'API resolution',
        'LoadLibraryA': 'library loading',
        'LoadLibraryW': 'library loading',
        'DllMain': 'DLL entry point',
    }

    @staticmethod
    def extract_from_imports(data: bytes) -> Dict[str, List[str]]:
        """Extract imported API names from PE/ELF data."""
        apis = {'suspicious': [], 'standard': []}
        
        # Look for API names as strings (common in compiled code)
        for api_name, description in WindowsAPIExtractor.SUSPICIOUS_APIS.items():
            # Search for ASCII string
            api_bytes = api_name.encode('ascii')
            if api_bytes in data:
                apis['suspicious'].append(api_name)
        
        # Also detect common API prefixes in binary
        patterns = [
            b'Kernel32',
            b'ntdll',
            b'ws2_32',
            b'wininet',
            b'advapi32',
            b'user32',
        ]
        
        for pattern in patterns:
            if pattern in data:
                apis['standard'].append(pattern.decode('ascii', errors='ignore'))
        
        return apis

    @staticmethod
    def analyze_api_calls(data: bytes) -> Dict[str, Any]:
        """Analyze API call patterns for risk."""
        apis = WindowsAPIExtractor.extract_from_imports(data)
        
        risk_level = 'LOW'
        if len(apis['suspicious']) >= 3:
            risk_level = 'CRITICAL'
        elif len(apis['suspicious']) >= 1:
            risk_level = 'HIGH'
        
        return {
            'suspicious_apis': apis['suspicious'],
            'standard_dlls': apis['standard'],
            'api_count': len(apis['suspicious']),
            'risk_level': risk_level,
        }


class ConfigExtractor:
    """Extract configuration strings and IOCs from payloads."""

    @staticmethod
    def extract_iocs(data: bytes) -> Dict[str, List[str]]:
        """Extract indicators of compromise (URLs, IPs, domains)."""
        strings = StringExtractor.extract_strings(data)
        text = '\n'.join(strings)
        
        iocs = {
            'urls': [],
            'domains': [],
            'ips': [],
            'emails': [],
            'hashes': [],
        }
        
        # URLs
        iocs['urls'] = re.findall(r'https?://[^\s]+', text)
        
        # Domains
        iocs['domains'] = re.findall(
            r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}',
            text, re.IGNORECASE
        )
        
        # IPs
        iocs['ips'] = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
        
        # Emails
        iocs['emails'] = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', text)
        
        # Hash values (MD5, SHA1, SHA256)
        iocs['hashes'] = list(set(re.findall(r'\b[0-9a-f]{32}\b', text, re.IGNORECASE)))  # MD5
        iocs['hashes'].extend(re.findall(r'\b[0-9a-f]{40}\b', text, re.IGNORECASE))  # SHA1
        iocs['hashes'].extend(re.findall(r'\b[0-9a-f]{64}\b', text, re.IGNORECASE))  # SHA256
        
        # Deduplicate
        for key in iocs:
            iocs[key] = list(set(iocs[key]))
        
        return iocs

    @staticmethod
    def extract_config(data: bytes) -> Dict[str, Any]:
        """Extract potential malware configuration."""
        iocs = ConfigExtractor.extract_iocs(data)
        
        config = {
            'potential_c2_servers': iocs['domains'] + iocs['ips'],
            'download_urls': [url for url in iocs['urls'] if 'http' in url.lower()],
            'contact_emails': iocs['emails'],
            'file_hashes': iocs['hashes'],
            'suspected_config': len(iocs['urls']) > 0 or len(iocs['domains']) > 0,
        }
        
        return config


class StringExtractor:
    """Helper for string extraction."""

    @staticmethod
    def extract_strings(data: bytes, min_length: int = 4) -> List[str]:
        """Extract readable strings."""
        strings = []
        current = bytearray()

        for byte in data:
            if (32 <= byte <= 126) or byte in (9, 10, 13):
                current.append(byte)
            else:
                if len(current) >= min_length:
                    try:
                        strings.append(current.decode('utf-8', errors='ignore'))
                    except Exception:
                        pass
                current = bytearray()

        if len(current) >= min_length:
            try:
                strings.append(current.decode('utf-8', errors='ignore'))
            except Exception:
                pass

        return strings
