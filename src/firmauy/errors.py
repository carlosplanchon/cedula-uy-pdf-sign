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


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------


class DetachedOriginalRequiredError(FirmaUYError):
    """A detached ``.p7s`` was given with no original file to check it against.

    The default follows the ``<x>.p7s -> <x>`` convention; this is raised when that sibling is
    missing and no ``original`` was passed. ``p7s_path`` is the signature and ``expected`` is
    where the original was looked for, so a caller can name the file it needs.

    A recoverable situation rather than a programming error: the two files routinely travel
    separately by email, and the fix is to ask which file the signature covers.

    .. versionadded:: 1.10.0
       Previously a bare ``ValueError``, which left callers matching on the message text.
    """

    def __init__(self, message: str, *, p7s_path=None, expected=None):
        super().__init__(message)
        self.p7s_path = p7s_path
        self.expected = expected


# ---------------------------------------------------------------------------
# Batches
# ---------------------------------------------------------------------------


class BatchSignCancelled(FirmaUYError):
    """The caller asked a batch to stop, and it did, between files.

    ``completed`` holds one :class:`~firmauy.api.SignReport` per file written before the stop, and
    ``stopped_before`` is the index of the first file that was never attempted. Everything in
    ``completed`` is on disk and valid.

    Deliberately **not** a :class:`BatchSignError`: somebody pressing cancel is not a failure, and
    a caller reporting "it broke" should not catch it by accident. Both carry ``completed``
    because both leave real signatures behind.

    The stop is only ever honoured between files. A signature is written whole or not at all, so
    there is no point at which a half-written output could be left behind.

    .. versionadded:: 1.11.0
    """

    def __init__(self, message: str, *, completed=None, stopped_before: int = -1):
        super().__init__(message)
        self.completed = list(completed or [])
        self.stopped_before = stopped_before


class BatchSignError(FirmaUYError):
    """A batch stopped at one file, carrying what had already been signed.

    ``completed`` holds one :class:`~firmauy.api.SignReport` per file written before the failure,
    ``failed_index`` is the position of the file that broke (0-based, into the input sequence)
    and ``failed_path`` is that file. The underlying failure is chained as ``__cause__``.

    The signatures already written stay on disk on purpose: they are real and valid. Being able
    to tell the user "2 of 7 were signed and they are fine" instead of only "it failed" is the
    reason this class exists.

    .. versionadded:: 1.10.0
    """

    def __init__(self, message: str, *, completed=None, failed_index: int = -1,
                 failed_path=None):
        super().__init__(message)
        self.completed = list(completed or [])
        self.failed_index = failed_index
        self.failed_path = failed_path
