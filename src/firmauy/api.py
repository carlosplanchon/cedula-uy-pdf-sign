"""Public library API for firmauy: verify, sign and diagnose as plain function calls.

These are thin, integration-friendly wrappers over the same logic the CLI uses. They
return the dataclasses from ``verify_common`` (and small report objects), never printed
output or process exit codes, so a GUI or another program can consume them directly.

Note: some orchestration helpers are still imported from ``firmauy.cli`` here. Moving
them to a shared module (so the CLI imports them from the API, not the other way round)
is a planned cleanup; it does not change these signatures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union

from firmauy.cms_verify import verify_cms
from firmauy.pdf_verify import verify_pdf
from firmauy.verify_common import VerifyResult
from firmauy.xml_verify import verify_xml


@dataclass
class VerifyReport:
    """Overall verdict plus the per-signature results."""

    indication: str  # VALID / INDETERMINATE / INVALID
    signatures: list[VerifyResult] = field(default_factory=list)


@dataclass
class DoctorCheck:
    """One environment check: ``status`` is PASS / WARN / FAIL, ``fix`` a hint when not PASS."""

    status: str
    name: str
    detail: str = ""
    fix: Optional[str] = None


@dataclass
class DoctorReport:
    """Diagnostic result: ``ok`` is True when no check FAILed (a WARN does not fail)."""

    ok: bool
    checks: list[DoctorCheck] = field(default_factory=list)


@dataclass
class SignReport:
    """Result of a successful signature: where it was written and who signed."""

    output_path: Path
    signer: str  # signer certificate common name
    issuer: str  # issuer certificate common name


def verify_file(
    path: Union[str, Path],
    *,
    original: Optional[Union[str, Path]] = None,
    ca_file: Optional[Union[str, Path]] = None,
    no_trust: bool = False,
    check_revocation: bool = False,
    tsa_ca: Optional[Union[str, Path]] = None,
) -> VerifyReport:
    """Verify a signed file (PDF, XAdES XML or detached CMS ``.p7s``), auto-detecting the format.

    Returns a :class:`VerifyReport` with the overall ``indication`` and the per-signature
    :class:`~firmauy.verify_common.VerifyResult` objects. Needs no card or PIN.

    For a detached ``.p7s``, ``original`` is the file it signs; by default the
    ``<x>.p7s -> <x>`` convention is used.
    """
    # Reuse the CLI's orchestration helpers (a later cleanup moves these to a shared module).
    from firmauy.cli import (
        _INDICATION_RANK,
        _detached_original,
        _detect_signature_kind,
        _resolve_trust_anchors,
        _resolve_tsa_anchors,
    )

    path = Path(path)
    kind = _detect_signature_kind(path)
    roots, intermediates = _resolve_trust_anchors(Path(ca_file) if ca_file else None, no_trust)

    if kind == "pdf":
        results = verify_pdf(path, trust_roots=roots, intermediates=intermediates,
                             check_revocation=check_revocation)
    elif kind == "xml":
        tsa_roots, tsa_others = _resolve_tsa_anchors(Path(tsa_ca) if tsa_ca else None)
        results = verify_xml(path.read_bytes(), trust_roots=roots, intermediates=intermediates,
                             check_revocation=check_revocation,
                             tsa_trust_roots=tsa_roots, tsa_other_certs=tsa_others)
    else:  # cms / detached .p7s
        orig = Path(original) if original else _detached_original(path)
        if orig is None or not orig.exists():
            raise ValueError("detached .p7s needs its original file (pass original=...)")
        with orig.open("rb") as data:
            results = [verify_cms(data, path.read_bytes(), trust_roots=roots,
                                  intermediates=intermediates, check_revocation=check_revocation)]

    overall = (max((r.indication for r in results), key=lambda ind: _INDICATION_RANK[ind])
               if results else "INDETERMINATE")
    return VerifyReport(indication=overall, signatures=list(results))


def run_doctor(
    *,
    native: bool = True,
    reader: Optional[Union[str, Path]] = None,
    pkcs11_lib: Optional[Union[str, Path]] = None,
) -> DoctorReport:
    """Diagnose the local signing environment and return the checks as data.

    Runs the same probes as the ``doctor`` command (firmauy version, pcscd, the smart-card
    backend and the bundled CA certificates), but prints nothing and never exits. Returns a
    :class:`DoctorReport`; ``report.ok`` is False when any check FAILed. Needs no card or PIN.

    ``native`` defaults to True (the PC/SC reader-and-card path that native signing uses),
    which is what the desktop app relies on; set it False to check the PKCS#11 middleware
    module at ``pkcs11_lib`` instead. ``reader`` selects a PC/SC reader for the native path.
    """
    # Reuse the CLI's check-gathering helper (a later cleanup moves it to a shared module).
    from firmauy.cli import DEFAULT_PKCS11_LIB, _collect_doctor_checks

    lib = str(pkcs11_lib) if pkcs11_lib is not None else DEFAULT_PKCS11_LIB
    raw = _collect_doctor_checks(native, str(reader) if reader is not None else None, lib)
    checks = [DoctorCheck(c["status"], c["name"], c.get("detail", ""), c.get("fix")) for c in raw]
    ok = all(c.status != "FAIL" for c in checks)
    return DoctorReport(ok=ok, checks=checks)


def sign_file(
    path: Union[str, Path],
    pin: str,
    *,
    output: Optional[Union[str, Path]] = None,
    native: bool = True,
    reader: Optional[Union[str, Path]] = None,
    pkcs11_lib: Optional[Union[str, Path]] = None,
    token_label: Optional[str] = None,
    cert_id: Optional[str] = None,
    tsa_url: Optional[str] = None,
    overwrite: bool = False,
    verify: bool = False,
) -> SignReport:
    """Sign ``path`` with the cédula, producing a detached CAdES-BES ``.p7s`` (CMS/PKCS#7).

    This is the programmatic form of ``sign-any``: the original file is left untouched and a
    detached signature is written next to it (``<path>.p7s`` by default, or ``output``). Returns
    a :class:`SignReport`; raises on any error (bad PIN, missing card, existing output, ...).

    ``pin`` is the card's User PIN, supplied directly (never a prompt); it is verified only after
    the PIN-free certificate read, so a reader/card problem cannot spend a card retry.

    ``native`` defaults to True (the PC/SC backend the desktop app uses), where ``reader`` picks a
    PC/SC reader. Set it False for a PKCS#11 module: ``pkcs11_lib`` is the module path (the bundled
    middleware by default, or e.g. OpenSC's ``opensc-pkcs11.so``), ``token_label`` picks a token and
    ``cert_id`` (hex) pins the signing certificate. ``tsa_url`` adds an RFC 3161 timestamp. With
    ``verify`` the fresh signature is re-checked for integrity (no trust) before returning.
    """
    from firmauy.cli import (
        DEFAULT_PKCS11_LIB,
        _build_timestamper,
        _sign_one_cms,
        _signing_session,
        _verify_after_cms,
    )
    from firmauy.pin import PinSource

    if not pin:
        # An empty PIN would still count toward the card's retry limit; refuse before contacting it.
        raise ValueError("a non-empty PIN is required to sign")

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"file to sign not found: {path}")
    out = Path(output) if output else path.with_name(path.name + ".p7s")
    if path.resolve() == out.resolve():
        raise ValueError("input and output are the same file; pass a different output=")

    timestamper = _build_timestamper(
        tsa_url=tsa_url, tsa_user=None, tsa_pass_env=None, tsa_header=None, tsa_header_env=None,
    )

    with _signing_session(
        native=native, reader=str(reader) if reader is not None else None,
        pkcs11_lib=str(pkcs11_lib) if pkcs11_lib is not None else DEFAULT_PKCS11_LIB,
        token_label=token_label, cert_id=cert_id,
        # pin_source is inert here: the direct ``pin`` below is used, so no prompt/read happens.
        pin_source=PinSource.prompt, pin_env_var=None, pin_fd=None,
        tsa_url=tsa_url, quiet=True, pin=pin, emit_notes=False,
    ) as ctx:
        _sign_one_cms(
            input_file=path, output_p7s=out, pkcs11_signer=ctx.pyhanko_signer(),
            timestamper=timestamper, overwrite=overwrite,
        )
        signer, issuer = ctx.signer_name, ctx.issuer_name

    if verify:
        _verify_after_cms(path, out)
    return SignReport(output_path=out, signer=signer, issuer=issuer)
