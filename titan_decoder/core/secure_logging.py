"""Structured logging with PII redaction for operational safety.

Provides a logging wrapper that automatically redacts sensitive information
like email addresses, IP addresses, and other PII from log messages.
"""

from __future__ import annotations

import logging
import re


class PIIRedactor:
    """Redact PII from log messages."""

    # Regex patterns for common PII
    EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    IP_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    HASH_PATTERN = re.compile(r"\b[a-fA-F0-9]{32,128}\b")

    @classmethod
    def redact(cls, message: str) -> str:
        """Redact PII from a message."""
        # Redact emails
        message = cls.EMAIL_PATTERN.sub("[EMAIL_REDACTED]", message)

        # Redact IPs (but preserve last octet for debugging)
        def redact_ip(match):
            ip = match.group(0)
            parts = ip.split(".")
            if len(parts) == 4:
                return f"XXX.XXX.XXX.{parts[3]}"
            return "[IP_REDACTED]"

        message = cls.IP_PATTERN.sub(redact_ip, message)

        # Redact long hashes (keep first 8 chars)
        def redact_hash(match):
            h = match.group(0)
            if len(h) >= 32:
                return f"{h[:8]}...[HASH_REDACTED]"
            return h

        message = cls.HASH_PATTERN.sub(redact_hash, message)

        return message


class RedactingFilter(logging.Filter):
    """Logging filter that redacts PII."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = PIIRedactor.redact(str(record.msg))
        if record.args:
            record.args = tuple(
                PIIRedactor.redact(str(arg)) if isinstance(arg, str) else arg
                for arg in record.args
            )
        return True


class StructuredLogger:
    """Structured logger with PII redaction."""

    def __init__(self, name: str, enable_redaction: bool = True):
        self.logger = logging.getLogger(name)
        self.enable_redaction = enable_redaction

        if enable_redaction:
            self.logger.addFilter(RedactingFilter())

    def debug(self, msg: str, **kwargs):
        """Log debug message with structured data."""
        self._log(logging.DEBUG, msg, kwargs)

    def info(self, msg: str, **kwargs):
        """Log info message with structured data."""
        self._log(logging.INFO, msg, kwargs)

    def warning(self, msg: str, **kwargs):
        """Log warning message with structured data."""
        self._log(logging.WARNING, msg, kwargs)

    def error(self, msg: str, **kwargs):
        """Log error message with structured data."""
        self._log(logging.ERROR, msg, kwargs)

    def critical(self, msg: str, **kwargs):
        """Log critical message with structured data."""
        self._log(logging.CRITICAL, msg, kwargs)

    def _log(self, level: int, msg: str, extra_data: dict):
        """Internal logging with structured data."""
        if extra_data:
            # Format structured data as key=value pairs
            structured = " ".join(f"{k}={v}" for k, v in extra_data.items())
            full_msg = f"{msg} [{structured}]"
        else:
            full_msg = msg

        self.logger.log(level, full_msg)


def setup_secure_logging(
    log_level: str = "INFO", enable_redaction: bool = True
) -> StructuredLogger:
    """Setup secure logging with PII redaction."""
    level = getattr(logging, log_level.upper(), logging.INFO)

    # Configure root logger
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Create structured logger
    logger = StructuredLogger("titan_decoder", enable_redaction=enable_redaction)

    return logger
