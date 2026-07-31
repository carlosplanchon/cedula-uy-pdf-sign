# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""Domain exceptions for firmauy.

They all derive from :class:`FirmaUYError`, so a caller can catch the whole family or a precise
condition::

    from firmauy.api import sign, IncorrectPinError, PinLockedError

    try:
        report = sign(path, pin_provider=ask_pin)
    except IncorrectPinError as exc:
        retry_dialog(attempts=exc.attempts_remaining)   # None when the backend cannot know
    except PinLockedError:
        show_unblock_help()

The hierarchy is intentionally small: only conditions a caller can meaningfully branch on get a
class. Environment problems (pcscd down, PKCS#11 module missing) stay plain ``RuntimeError`` with
actionable messages, and ``run_doctor`` is the structured way to diagnose those. That split is the
point of keeping ``FirmaUYError`` off the built-in error types: an expected domain condition and an
unexpected failure should not be caught by the same ``except``.
"""

from typing import Optional


class FirmaUYError(Exception):
    """Base class for all firmauy domain errors."""


# ---------------------------------------------------------------------------
# Reader / card presence (PC/SC)
# ---------------------------------------------------------------------------


class ReaderNotFoundError(FirmaUYError):
    """No PC/SC reader is available (none connected, or the named reader does not exist)."""


class CardNotFoundError(FirmaUYError):
    """A reader is present but no card answered (not inserted, or not readable)."""


# ---------------------------------------------------------------------------
# PIN
# ---------------------------------------------------------------------------


class PinError(FirmaUYError):
    """Base class for PIN problems (bad format, empty, or the low-retries safety guard)."""


class IncorrectPinError(PinError):
    """The PIN was wrong. ``attempts_remaining`` is the card's remaining tries when the backend
    can know it (the native PC/SC path), or None (the PKCS#11 middleware does not report it)."""

    def __init__(self, message: str, *, attempts_remaining: Optional[int] = None):
        super().__init__(message)
        self.attempts_remaining = attempts_remaining


class PinLockedError(PinError):
    """The PIN is blocked after too many incorrect attempts; the cédula must be unblocked."""


# ---------------------------------------------------------------------------
# Tokens / certificates
# ---------------------------------------------------------------------------


class TokenNotFoundError(FirmaUYError):
    """No PKCS#11 token is available to the module."""


class CertificateError(FirmaUYError):
    """Base class for signing-certificate problems on the card/token."""


class CertificateNotFoundError(CertificateError):
    """No (matching) certificate exists on the token."""


class CertificateNotValidError(CertificateError):
    """The signing certificate is outside its validity window (expired, or not yet valid)."""


class SigningKeyNotFoundError(CertificateError):
    """A certificate exists but has no matching private key to sign with."""


# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------


class OutputExistsError(FirmaUYError):
    """The output file already exists and overwrite was not requested. ``path`` is the output."""

    def __init__(self, message: str, *, path=None):
        super().__init__(message)
        self.path = path
