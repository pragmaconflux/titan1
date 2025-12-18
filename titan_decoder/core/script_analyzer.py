"""Script analyzers for PowerShell, Bash, JavaScript, and shellcode detection."""

import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class ScriptAnalysis:
    """Results of script analysis."""

    script_type: str
    obfuscation_score: float  # 0-1, higher = more obfuscated
    suspicious_patterns: List[str]
    extracted_strings: List[str]
    commands: List[str]
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL


class PowerShellAnalyzer:
    """Analyze PowerShell scripts for malicious patterns."""

    # Suspicious cmdlets and patterns
    SUSPICIOUS_CMDLETS = {
        "IEX": "code execution (Invoke-Expression)",
        "Invoke-WebRequest": "download capability",
        "DownloadFile": "file download",
        "DownloadString": "data download",
        "WriteAllBytes": "file write",
        "Reflection.Assembly": "reflection/injection",
        "GetMethod": "method invocation",
        "Invoke-Item": "execution",
        "Start-Process": "process execution",
        "New-Object": "object creation",
        "ExpandEnvironmentVariables": "variable expansion",
        "ConvertFrom-SecureString": "credential access",
    }

    @staticmethod
    def analyze(data: bytes) -> Optional[ScriptAnalysis]:
        """Analyze PowerShell script."""
        try:
            text = data.decode("utf-8", errors="ignore")

            # Check if it looks like PowerShell
            if not any(kw in text for kw in ["$", "Write-", "Invoke-", "Get-", "Set-"]):
                return None

            analysis = ScriptAnalysis(
                script_type="PowerShell",
                obfuscation_score=0.0,
                suspicious_patterns=[],
                extracted_strings=[],
                commands=[],
                risk_level="LOW",
            )

            # Find suspicious cmdlets
            for cmdlet, desc in PowerShellAnalyzer.SUSPICIOUS_CMDLETS.items():
                if re.search(re.escape(cmdlet), text, re.IGNORECASE):
                    analysis.suspicious_patterns.append(f"{cmdlet}: {desc}")

            # Detect obfuscation techniques
            obfuscation_indicators = [
                r"\$\{\w+\}",  # Variable expansion
                r"[A-Za-z0-9+/]{50,}={0,2}(?=\s|$)",  # Base64 inline
                r"'\s*\+\s*'",  # String concatenation
                r"\[char\]",  # Char conversion
                r"IEX\s*\(",  # Code execution
            ]

            obfuscation_count = sum(
                1 for pattern in obfuscation_indicators if re.search(pattern, text)
            )
            analysis.obfuscation_score = min(
                1.0, obfuscation_count / len(obfuscation_indicators)
            )

            # Extract strings in quotes
            strings = re.findall(r"'([^']{10,})'|\"([^\"{10,}]\")", text)
            analysis.extracted_strings = [s[0] or s[1] for s in strings[:10]]

            # Extract commands
            commands = re.findall(r"((?:Invoke-|Get-|Set-|New-)\w+)", text)
            analysis.commands = list(set(commands))

            # Risk assessment
            risk_factors = len(analysis.suspicious_patterns) + (
                analysis.obfuscation_score * 3
            )
            if risk_factors >= 4:
                analysis.risk_level = "CRITICAL"
            elif risk_factors >= 2:
                analysis.risk_level = "HIGH"
            elif risk_factors >= 1:
                analysis.risk_level = "MEDIUM"

            return analysis
        except Exception:
            return None


class BashAnalyzer:
    """Analyze Bash/Shell scripts for malicious patterns."""

    SUSPICIOUS_PATTERNS = {
        r"curl.*\|.*bash": "pipe curl to bash execution",
        r"wget.*\|.*bash": "pipe wget to bash execution",
        r"nc\s+-l": "netcat listener (reverse shell)",
        r"/bin/bash.*-i": "interactive bash (reverse shell)",
        r"exec.*</dev/tcp": "TCP socket exploitation",
        r"dd.*if=/dev/": "low-level device access",
        r"chmod\s+777": "world-writable permissions",
        r"eval\s*\(": "code evaluation",
        r"\$\(\s*cat": "command substitution",
    }

    @staticmethod
    def analyze(data: bytes) -> Optional[ScriptAnalysis]:
        """Analyze Bash script."""
        try:
            text = data.decode("utf-8", errors="ignore")

            # Check if it looks like Bash
            if not (
                text.strip().startswith("#!/bin/bash")
                or text.strip().startswith("#!/bin/sh")
                or any(kw in text for kw in ["${", "$((", "for ", "if ["])
            ):
                return None

            analysis = ScriptAnalysis(
                script_type="Bash/Shell",
                obfuscation_score=0.0,
                suspicious_patterns=[],
                extracted_strings=[],
                commands=[],
                risk_level="LOW",
            )

            # Find suspicious patterns
            for pattern, desc in BashAnalyzer.SUSPICIOUS_PATTERNS.items():
                if re.search(pattern, text, re.IGNORECASE):
                    analysis.suspicious_patterns.append(f"{desc}")

            # Detect obfuscation (encoding, variable nesting)
            obfuscation = 0
            if re.search(r"echo.*base64", text):
                obfuscation += 1
            if re.search(r"\${.*\${", text):  # Nested variables
                obfuscation += 1
            if len(re.findall(r"\$\{[^}]+\}", text)) > 5:
                obfuscation += 1

            analysis.obfuscation_score = min(1.0, obfuscation / 3.0)

            # Extract commands
            commands = re.findall(
                r"(?:^|\s)((?:[a-z0-9_-]+)(?:\s+\||\s+&&|\s+\|\||;|$))", text
            )
            analysis.commands = list(
                set([cmd.strip().rstrip(";|&") for cmd in commands[:15]])
            )

            # Risk assessment
            if len(analysis.suspicious_patterns) >= 2 or "reverse shell" in str(
                analysis.suspicious_patterns
            ):
                analysis.risk_level = "CRITICAL"
            elif len(analysis.suspicious_patterns) >= 1:
                analysis.risk_level = "HIGH"

            return analysis
        except Exception:
            return None


class ShellcodeDetector:
    """Detect and analyze x86/x64 shellcode."""

    # Common shellcode patterns
    SHELLCODE_PATTERNS = {
        b"\x55\x89\xe5": "x86 push ebp; mov ebp, esp (function prologue)",
        b"\x48\x89\xe5": "x64 push rbp; mov rbp, rsp (function prologue)",
        b"\xcd\x80": "x86 int 0x80 (syscall)",
        b"\x0f\x05": "x64 syscall",
        b"\xff\x25": "x86 jmp indirect (common in shellcode)",
        b"\x90\x90\x90": "NOP sled",
        b"\xeb": "jmp (loop back)",
    }

    @staticmethod
    def detect_shellcode(data: bytes) -> Optional[Dict[str, Any]]:
        """Detect if data contains shellcode."""
        if len(data) < 4:
            return None

        matches = []
        for pattern, desc in ShellcodeDetector.SHELLCODE_PATTERNS.items():
            count = data.count(pattern)
            if count > 0:
                matches.append({"pattern": desc, "count": count})

        if not matches:
            return None

        # Check for entropy (high entropy = likely code)
        entropy = ShellcodeDetector._calculate_entropy(data)

        return {
            "is_shellcode": True,
            "patterns": matches,
            "entropy": entropy,
            "length": len(data),
            "confidence": min(1.0, len(matches) / 3.0)
            * (1.0 if entropy > 5.5 else 0.7),
        }

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy."""
        if not data:
            return 0.0
        from collections import Counter
        import math

        counts = Counter(data)
        entropy = -sum(
            (count / len(data)) * math.log2(count / len(data))
            for count in counts.values()
        )
        return entropy


class JavaScriptAnalyzer:
    """Analyze JavaScript for suspicious patterns."""

    SUSPICIOUS_JS = {
        r"eval\s*\(": "code evaluation",
        r"Function\s*\(": "dynamic function creation",
        r"document\.write": "DOM manipulation",
        r"innerHTML": "HTML injection",
        r"XMLHttpRequest|fetch\s*\(": "network request",
        r"localStorage|sessionStorage": "client storage access",
        r"window\.location": "navigation",
        r"atob\s*\(": "base64 decode",
        r"String\.fromCharCode": "char code conversion (obfuscation)",
        r"\.replace\s*\(/.*?/": "string replacement (obfuscation)",
    }

    @staticmethod
    def analyze(data: bytes) -> Optional[ScriptAnalysis]:
        """Analyze JavaScript."""
        try:
            text = data.decode("utf-8", errors="ignore")

            # Quick check
            if "function" not in text and "var " not in text and "=" not in text:
                return None

            analysis = ScriptAnalysis(
                script_type="JavaScript",
                obfuscation_score=0.0,
                suspicious_patterns=[],
                extracted_strings=[],
                commands=[],
                risk_level="LOW",
            )

            for pattern, desc in JavaScriptAnalyzer.SUSPICIOUS_JS.items():
                if re.search(pattern, text, re.IGNORECASE):
                    analysis.suspicious_patterns.append(f"{desc}")

            # Detect obfuscation
            obfuscation = 0
            if len(re.findall(r"\w{20,}", text)) > 3:  # Long variable names
                obfuscation += 1
            if re.search(r"String\.fromCharCode\s*\([0-9,\s]+\)", text):
                obfuscation += 1
            if re.search(r'\.replace\([\'"]./[\'"][,\)][,\)]', text):
                obfuscation += 1

            analysis.obfuscation_score = min(1.0, obfuscation / 3.0)

            # Risk assessment
            if len(analysis.suspicious_patterns) >= 3:
                analysis.risk_level = "HIGH"
            elif len(analysis.suspicious_patterns) >= 1:
                analysis.risk_level = "MEDIUM"

            return analysis
        except Exception:
            return None
