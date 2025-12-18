from titan_decoder.core.secure_logging import PIIRedactor, setup_secure_logging


def test_email_redaction():
    message = "Contact admin@example.com for help"
    redacted = PIIRedactor.redact(message)
    assert "[EMAIL_REDACTED]" in redacted
    assert "admin@example.com" not in redacted


def test_ip_redaction():
    message = "Server at 192.168.1.100 is down"
    redacted = PIIRedactor.redact(message)
    assert "XXX.XXX.XXX.100" in redacted
    assert "192.168.1.100" not in redacted


def test_hash_redaction():
    message = "Hash: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    redacted = PIIRedactor.redact(message)
    assert "[HASH_REDACTED]" in redacted
    assert "a1b2c3d4" in redacted  # First 8 chars preserved
    assert message not in redacted


def test_setup_secure_logging():
    logger = setup_secure_logging("INFO", enable_redaction=True)
    assert logger is not None
    assert logger.enable_redaction is True
