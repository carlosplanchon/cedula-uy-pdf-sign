# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""Card-signing engine shared by the CLI and the public API.

This module holds the signing machinery (session management, per-format signers,
timestamping and post-sign verification) so both firmauy.cli and firmauy.api build on it,
instead of the public API reaching into the CLI module. It is presentation-free: it never
prints or exits. Warnings and notes are reported through an optional ``notify`` callback
(the CLI passes a stderr printer, the API passes nothing), the identity display fields
travel on the yielded ``_SigningContext`` for the caller to print, and the PIN arrives
directly (``pin``) or lazily (``pin_provider``), never via a prompt of its own."""

import os
import tempfile
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Callable, List, Optional
from zoneinfo import ZoneInfo
import pkcs11
import pkcs11.exceptions
from cryptography import x509
from pyhanko import stamp
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.layout import (
    AxisAlignment,
    InnerScaling,
    Margins,
    SimpleBoxLayoutRule,
)
from pyhanko.sign import fields, signers
from pyhanko.sign.pkcs11 import PKCS11Signer
from pyhanko.sign.timestamps import HTTPTimeStamper
from firmauy.appearance import ensure_output_parent, make_appearance_pdf
from firmauy.card_reader import (
    open_reader,
    select_applet,
)
from firmauy.cert_utils import (
    cert_not_after,
    cert_not_before,
    get_common_name,
    normalize_issuer_name,
)
from firmauy.errors import (
    CertificateNotValidError,
    IncorrectPinError,
    OutputExistsError,
    PinError,
    PinLockedError,
)
from firmauy.constants import (
    DEFAULT_IMAGE_OPACITY,
    DEFAULT_PKCS11_LIB,
    ImageMode,
    SignAs,
)
from firmauy.pkcs11_utils import (
    cert_is_expired,
    cert_not_yet_valid,
    find_token,
    get_private_key,
    load_pkcs11_lib,
    normalize_cert_id_hex,
    select_certificate,
)
from firmauy.pdf_verify import verify_pdf
from firmauy.xml_sign import sign_xml
from firmauy.xml_verify import verify_xml
from firmauy.cms_sign import sign_cms_detached
from firmauy.cms_verify import verify_cms


class _SigningContext:
    """Backend-agnostic context yielded by ``_signing_session``.

    Carries the selected certificate and its display fields, plus lazy factories for the two signer
    shapes the sign-* commands need: a pyHanko ``Signer`` (PDF/CMS) via ``pyhanko_signer()`` and a raw
    bytes->bytes callable (XML) via ``raw_signer()``. The factories are backend-specific (PKCS#11 vs
    native card); each is built at most once, so a PDF-only sign never constructs the XML signer and
    vice-versa, and a batch reuses the one instance across all files.

    ``source_caption`` ("Token" / "Reader"), ``source_display`` (token label / resolved reader name)
    and ``key_id`` (the PKCS#11 object ID, None in native mode) let the caller print the identity
    block; the session itself prints nothing."""

    def __init__(self, *, cert, signer_name, issuer_name, cert_serial,
                 source_caption, source_display, key_id,
                 pyhanko_signer_factory, raw_signer_factory):
        self.cert = cert
        self.signer_name = signer_name
        self.issuer_name = issuer_name
        self.cert_serial = cert_serial
        self.source_caption = source_caption
        self.source_display = source_display
        self.key_id = key_id
        self._pyhanko_signer_factory = pyhanko_signer_factory
        self._raw_signer_factory = raw_signer_factory
        self._pyhanko_signer = None
        self._raw_signer = None

    def pyhanko_signer(self):
        if self._pyhanko_signer is None:
            self._pyhanko_signer = self._pyhanko_signer_factory()
        return self._pyhanko_signer

    def raw_signer(self):
        if self._raw_signer is None:
            self._raw_signer = self._raw_signer_factory()
        return self._raw_signer


def _cert_display_fields(cert) -> tuple:
    """The (signer_name, issuer_name, cert_serial) shown in the identity block, derived the same
    way by both signing backends."""
    return (
        get_common_name(cert.subject),
        normalize_issuer_name(get_common_name(cert.issuer)),
        format(cert.serial_number, "X"),
    )


@contextmanager
def _card_connection(reader_name=None):
    """Open a PC/SC card connection and always disconnect on exit (best-effort), shared by the
    native signing session and fetch-identity / fetch-photo."""
    conn = open_reader(reader_name)
    try:
        yield conn
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass


def _resolve_final_pin(pin, pin_provider) -> str:
    """Resolve the PIN at the point of use (after the PIN-free certificate read, so the card's
    retry-limit guard is preserved): a directly-supplied ``pin``, else the lazy ``pin_provider()``
    callback (the CLI wraps its --pin-source handling in one). Rejects an empty PIN before it can
    reach the card."""
    if pin is None and pin_provider is None:
        raise RuntimeError("no PIN was supplied: pass pin= or pin_provider=")
    final = pin if pin is not None else pin_provider()
    if not final:
        raise PinError(
            "Empty PIN received; aborting before contacting the card "
            "(an empty PIN would still count toward its retry limit)."
        )
    return final


@contextmanager
def _signing_session(*, native, reader, pkcs11_lib, token_label, cert_id, pin=None,
                     pin_provider=None, notify: Optional[Callable[[str], None]] = None):
    """Open a signing session with the selected backend and yield a ``_SigningContext``.

    Dispatches to the native PC/SC backend (``--native``) or the PKCS#11 backend. Both select the
    signing certificate and expose the same signer factories plus the identity display fields, so
    every sign-* command (single and batch) stays backend-agnostic; printing the identity block is
    the caller's job. Callers keep their own (fail-fast, pre-PIN) validation and timestamper build.

    The PIN arrives as ``pin`` (direct) or ``pin_provider`` (a zero-arg callable invoked only after
    the PIN-free certificate read, preserving the card's retry-limit guard). ``notify``, when given,
    receives the informational lines as they occur (backend-option notes pre-flight, then the
    certificate-selection warnings); without it they are dropped. The --cert-id/--native hard error
    is always raised."""
    _check_backend_options(
        native=native, reader=reader, pkcs11_lib=pkcs11_lib, token_label=token_label,
        cert_id=cert_id, notify=notify,
    )
    if native:
        with _native_signing_session(reader=reader, pin=pin, pin_provider=pin_provider) as ctx:
            yield ctx
    else:
        with _pkcs11_signing_session(
            pkcs11_lib=pkcs11_lib, token_label=token_label, cert_id=cert_id, pin=pin,
            pin_provider=pin_provider, notify=notify,
        ) as ctx:
            yield ctx


@contextmanager
def _pkcs11_signing_session(*, pkcs11_lib, token_label, cert_id, pin=None, pin_provider=None,
                            notify: Optional[Callable[[str], None]] = None):
    """PKCS#11 backend: load the module, open a PIN session, select the signing certificate and
    yield the context (display fields included, nothing printed). The session is closed on exit.
    ``notify`` receives the certificate-selection warnings (skipped candidates)."""
    # Validate the hex cert ID up front: a malformed --cert-id must fail before the PIN is obtained
    # (an incorrect PIN counts toward the card's retry limit), not later inside select_certificate.
    if cert_id is not None:
        normalize_cert_id_hex(cert_id)
    lib = load_pkcs11_lib(pkcs11_lib)
    token = find_token(lib, token_label)
    final_pin = _resolve_final_pin(pin, pin_provider)
    # Translate the middleware's PIN exceptions into the domain ones (same messages the CLI's
    # _format_error historically produced), so API consumers can catch IncorrectPinError /
    # PinLockedError regardless of backend. The middleware does not report remaining attempts.
    try:
        with token.open(user_pin=final_pin) as session:
            key_id, cert = select_certificate(session, cert_id, notify=notify)
            signer_name, issuer_name, cert_serial = _cert_display_fields(cert)
            yield _SigningContext(
                cert=cert, signer_name=signer_name, issuer_name=issuer_name,
                cert_serial=cert_serial,
                source_caption="Token",
                source_display=(getattr(token, "label", "") or "").strip() or "<no label>",
                key_id=key_id,
                pyhanko_signer_factory=lambda: PKCS11Signer(
                    pkcs11_session=session, cert_id=key_id, key_id=key_id),
                raw_signer_factory=lambda: _make_raw_signer(session, key_id),
            )
    except pkcs11.exceptions.PinIncorrect as exc:
        raise IncorrectPinError("Incorrect PIN.") from exc
    except pkcs11.exceptions.PinLocked as exc:
        raise PinLockedError("The PIN is locked (too many incorrect attempts).") from exc


@contextmanager
def _native_signing_session(*, reader, pin=None, pin_provider=None):
    """Native PC/SC backend: open the reader, select the applet, read the public signing certificate,
    verify the PIN and yield the context (display fields included, nothing printed). No PKCS#11
    module is loaded. The connection is closed on exit. Do not run while a PKCS#11 sign session is
    open on the same card: both go through pcscd and will conflict.

    The PIN (direct ``pin`` or lazy ``pin_provider``) is obtained only after the PIN-free
    certificate read, preserving the retry-limit guard."""
    from firmauy import native_card
    with _card_connection(reader) as conn:
        select_applet(conn)
        cert = native_card.read_signing_certificate(conn)
        # Same validity guard the PKCS#11 path gets from select_certificate: never sign with an
        # expired / not-yet-valid certificate, and fail before the PIN is obtained.
        if cert_is_expired(cert) or cert_not_yet_valid(cert):
            if cert_is_expired(cert):
                reason = f"expired (valid until {cert_not_after(cert)})"
            else:
                reason = f"not yet valid (valid from {cert_not_before(cert)})"
            raise CertificateNotValidError(
                f"The card's signing certificate is {reason}: {get_common_name(cert.subject)}"
            )
        signer_name, issuer_name, cert_serial = _cert_display_fields(cert)
        # Obtain the PIN only after the (PIN-free) cert read succeeds, so a reader/card problem
        # surfaces before the PIN is requested. verify_pin refuses to spend the card's last retry.
        final_pin = _resolve_final_pin(pin, pin_provider)
        native_card.verify_pin(conn, final_pin)
        # The pyHanko signer is built lazily through the factory (honoring _SigningContext's
        # contract: an XML-only sign never constructs it, nor loads the bundled trust anchors).
        sig_len = (cert.public_key().key_size + 7) // 8   # expected RSA signature size (256)
        yield _SigningContext(
            cert=cert, signer_name=signer_name, issuer_name=issuer_name, cert_serial=cert_serial,
            # The reader name pyscard resolved, so the identity block records the actual device
            # even when it was auto-detected rather than passed via ``reader``.
            source_caption="Reader", source_display=conn.getReader(), key_id=None,
            pyhanko_signer_factory=lambda: native_card.make_native_signer(conn, cert),
            raw_signer_factory=lambda: (
                lambda data: native_card.sign_message(conn, data, expected_len=sig_len)),
        )


_SENSITIVE_HEADERS = frozenset({
    "authorization", "proxy-authorization", "x-api-key", "api-key", "x-auth-token", "x-auth",
})


def _build_timestamper(
    *,
    tsa_url: Optional[str],
    tsa_user: Optional[str],
    tsa_pass_env: Optional[str],
    tsa_header: Optional[List[str]],
    tsa_header_env: Optional[List[str]],
    notify: Optional[Callable[[str], None]] = None,
):
    """Build an HTTPTimeStamper from the TSA options, or None when no --tsa-url is given.

    Supports HTTP Basic auth (``--tsa-user`` + ``--tsa-pass-env``) and arbitrary extra headers for
    credentialed RFC 3161 TSAs. A header value may be literal (``--tsa-header 'Name: Value'``) or,
    for a secret, read from an environment variable (``--tsa-header-env 'Name: ENV_VAR'``) so it
    never appears in argv. Passwords/secrets are never taken on the command line. Raises
    ``ValueError`` on inconsistent options. ``notify``, when given, receives the argv-visibility
    warning for a literal header whose name looks like a credential (a CLI-only concern)."""
    if tsa_url is None:
        if tsa_user or tsa_pass_env or tsa_header or tsa_header_env:
            raise ValueError(
                "--tsa-user / --tsa-pass-env / --tsa-header / --tsa-header-env require --tsa-url."
            )
        return None

    auth = None
    if tsa_user or tsa_pass_env:
        if not (tsa_user and tsa_pass_env):
            raise ValueError(
                "HTTP Basic auth for the TSA needs both --tsa-user and --tsa-pass-env."
            )
        password = os.environ.get(tsa_pass_env)
        if password is None:
            raise ValueError(
                f"Environment variable '{tsa_pass_env}' (from --tsa-pass-env) is not set."
            )
        auth = (tsa_user, password)

    headers: dict = {}
    # Literal headers: the value is on the command line. Warn if one looks like a credential.
    for item in (tsa_header or []):
        name, sep, value = item.partition(":")
        if not sep or not name.strip():
            raise ValueError(
                f"--tsa-header '{item}' must be in 'Name: Value' format."
            )
        nm = name.strip()
        if nm.lower() in _SENSITIVE_HEADERS and notify:
            notify(
                f"Warning: the value of --tsa-header '{nm}' is visible in the process list (argv). "
                "Use --tsa-header-env to read it from an environment variable instead."
            )
        headers[nm] = value.strip()
    # Env-backed headers: the value is read from an environment variable, kept off argv.
    for item in (tsa_header_env or []):
        name, sep, env_var = item.partition(":")
        if not sep or not name.strip() or not env_var.strip():
            raise ValueError(
                f"--tsa-header-env '{item}' must be in 'Name: ENV_VAR' format."
            )
        val = os.environ.get(env_var.strip())
        if val is None:
            raise ValueError(
                f"Environment variable '{env_var.strip()}' "
                f"(from --tsa-header-env '{name.strip()}') is not set."
            )
        headers[name.strip()] = val

    return HTTPTimeStamper(tsa_url, auth=auth, headers=headers or None)


def _check_backend_options(*, native, reader, pkcs11_lib, token_label, cert_id,
                           notify: Optional[Callable[[str], None]] = None) -> None:
    """Pre-flight (before any reader or PIN access): reject or warn about options that don't apply
    to the chosen backend.

    --cert-id is an identity-pinning guarantee ("sign only with this certificate") that the native
    backend cannot honor -- the card exposes a single signing certificate (EF B001) and there are no
    PKCS#11 object IDs to match -- so combining it with --native is a hard error, not a silently
    weakened warning. --pkcs11-lib/--token-label are harmless in native mode and only warn, and the
    pcscd single-card caveat applies (same wording as fetch-identity). --reader only applies to the
    native backend, so it is a no-op with PKCS#11.

    The informational notes go to ``notify`` (the CLI passes a stderr printer; the public API passes
    nothing and they are dropped); the --cert-id/--native hard error is always raised."""
    if native:
        if cert_id is not None:
            raise RuntimeError(
                "--cert-id cannot be used with --native: it pins the signing identity by PKCS#11 "
                "object ID, and the native backend always signs with the card's single signing "
                "certificate (EF B001). Drop --cert-id, or use the PKCS#11 backend to select a "
                "certificate by ID."
            )
        if notify is None:
            return
        ignored = [
            name for name, changed in (
                ("--pkcs11-lib", pkcs11_lib != DEFAULT_PKCS11_LIB),
                ("--token-label", token_label is not None),
            ) if changed
        ]
        if ignored:
            notify(
                f"Note: {', '.join(ignored)} {'is' if len(ignored) == 1 else 'are'} ignored with "
                "--native (no PKCS#11 module is used)."
            )
        notify(
            "Note: --native talks to the card over PC/SC; do not run while a PKCS#11 session (other "
            "sign-* invocations) is active on the same card -- both go through pcscd and may conflict."
        )
    elif reader is not None and notify is not None:
        notify(
            "Note: --reader only applies to --native; it is ignored with the PKCS#11 backend."
        )


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` atomically: write a sibling ``.part`` then os.replace() it into
    place. os.replace() *replaces* an output symlink with the file instead of writing through it (so
    a pre-existing symlink at ``path`` cannot redirect the bytes elsewhere), and an interrupted write
    never leaves a truncated file at ``path`` -- the same guarantees the PDF signing path relies on."""
    tmp = path.with_name(path.name + ".part")
    try:
        tmp.write_bytes(data)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _sign_one_pdf(
    *,
    input_pdf: Path,
    output_pdf: Path,
    pkcs11_signer: "PKCS11Signer",
    signer_name: str,
    issuer_name: str,
    cert_serial: str,
    timestamper,
    meta: "signers.PdfSignatureMetadata",
    page: int,
    x1: int,
    y1: int,
    x2: int,
    y2: int,
    timezone: str,
    field_name: str,
    force: bool,
    overwrite: bool,
    image_path: Optional[Path] = None,
    image_mode: ImageMode = ImageMode.background,
    image_opacity: float = DEFAULT_IMAGE_OPACITY,
    allow_hybrid_xref: bool = False,
    notify: Optional[Callable[[str], None]] = None,
) -> None:
    """Sign a single PDF. Raises on any error. ``notify``, when given, receives the warning lines
    (hybrid-xref opt-in, signature-field reuse); without it they are dropped."""
    if input_pdf.resolve() == output_pdf.resolve():
        raise RuntimeError(
            f"Input and output are the same file: {output_pdf}. "
            "Choose a different output path (in batch mode, adjust --output-dir or --suffix)."
        )
    if output_pdf.exists() and not overwrite:
        raise OutputExistsError(
            f"Output file already exists: {output_pdf}\n"
            "Use --overwrite to overwrite it.",
            path=output_pdf,
        )

    ensure_output_parent(output_pdf)

    with input_pdf.open("rb") as inf:
        # Hybrid cross-reference PDFs (a classic xref table + an xref stream, common in files
        # exported by design tools) can't be incrementally signed in strict mode: pyHanko refuses
        # because the two xref structures could desync and the signature would not be equivalent
        # for all readers. --allow-hybrid-xref opens the PDF non-strict to sign it anyway.
        writer = IncrementalPdfFileWriter(inf, strict=not allow_hybrid_xref)
        if writer.prev.xrefs.hybrid_xrefs_present:
            if not allow_hybrid_xref:
                raise RuntimeError(
                    f"{input_pdf.name} uses hybrid cross-reference sections, which cannot be "
                    "signed in strict mode (the incremental signature may not be equivalent for "
                    "all PDF readers). Normalize it first with `qpdf in.pdf out.pdf` and sign the "
                    "result, or pass --allow-hybrid-xref to sign it as-is (at your own risk)."
                )
            if notify:
                notify(
                    f"Warning: {input_pdf.name} has hybrid cross-reference sections. Signing due to "
                    "--allow-hybrid-xref. The signature may not be equivalent for older PDF readers."
                )

        existing_fields = list(fields.enumerate_sig_fields(writer))
        matching = [(name, val) for name, val, _ in existing_fields if name == field_name]
        if matching:
            _, field_value = matching[0]
            if field_value is not None:
                if not force:
                    raise RuntimeError(
                        f"Field '{field_name}' already contains a signature. "
                        "Use --force to continue anyway (the PDF may become invalid)."
                    )
                if notify:
                    notify(
                        f"Warning: field '{field_name}' already contains a signature. "
                        "Continuing due to --force (the PDF may become invalid)."
                    )
            elif notify:
                notify(
                    f"Warning: field '{field_name}' already exists but is unsigned, "
                    "it will be reused."
                )
        else:
            fields.append_signature_field(
                writer,
                sig_field_spec=fields.SigFieldSpec(
                    field_name,
                    on_page=page,
                    box=(x1, y1, x2, y2),
                ),
            )

        ts = datetime.now(ZoneInfo(timezone)).strftime("%d/%m/%Y %H:%M")

        appearance_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
                appearance_path = tmp.name

            make_appearance_pdf(
                appearance_path,
                signer=signer_name,
                cert_serial=cert_serial,
                ts=ts,
                issuer=issuer_name,
                image_path=str(image_path) if image_path else None,
                image_mode=image_mode,
                image_opacity=image_opacity,
            )

            pdf_signer = signers.PdfSigner(
                meta,
                signer=pkcs11_signer,
                timestamper=timestamper,
                stamp_style=stamp.StaticStampStyle.from_pdf_file(
                    appearance_path,
                    border_width=0,
                    background_layout=SimpleBoxLayoutRule(
                        x_align=AxisAlignment.ALIGN_MIN,
                        y_align=AxisAlignment.ALIGN_MIN,
                        margins=Margins(0, 0, 0, 0),
                        inner_content_scaling=InnerScaling.NO_SCALING,
                    ),
                ),
            )

            # Sign into a sibling temp file, then atomically move it into place. A failure
            # mid-signing (e.g. the card is pulled) then never leaves a partial/corrupt file at
            # output_pdf, and with --overwrite it never destroys the previous good output either.
            # (The XML/CMS paths get the same guarantee via _atomic_write_bytes.)
            # os.replace also *replaces* an output symlink with the signed file instead of writing
            # through it, so a pre-created symlink cannot redirect the output to another location.
            tmp_out = output_pdf.with_name(output_pdf.name + ".part")
            try:
                with tmp_out.open("wb") as outf:
                    pdf_signer.sign_pdf(writer, output=outf)
                os.replace(tmp_out, output_pdf)
            except BaseException:
                tmp_out.unlink(missing_ok=True)
                raise

        finally:
            if appearance_path:
                try:
                    Path(appearance_path).unlink(missing_ok=True)
                except Exception:
                    pass


def _make_raw_signer(session, key_id: bytes):
    """Return a callable that signs bytes on the token with RSA-SHA256."""
    priv = get_private_key(session, key_id)

    def raw_signer(data: bytes) -> bytes:
        return bytes(priv.sign(data, mechanism=pkcs11.Mechanism.SHA256_RSA_PKCS))

    return raw_signer


def _sign_one_xml(
    *,
    input_xml: Path,
    output_xml: Path,
    cert: "x509.Certificate",
    signer,
    signing_time: datetime,
    overwrite: bool,
    timestamper=None,
) -> None:
    """Sign a single XML (XAdES-BES, or XAdES-T with a timestamper). Raises on any error."""
    if input_xml.resolve() == output_xml.resolve():
        raise RuntimeError(
            f"Input and output are the same file: {output_xml}. "
            "Choose a different output path (in batch mode, adjust --output-dir or --suffix)."
        )
    if output_xml.exists() and not overwrite:
        raise OutputExistsError(
            f"Output file already exists: {output_xml}\n"
            "Use --overwrite to overwrite it.",
            path=output_xml,
        )
    ensure_output_parent(output_xml)
    signed = sign_xml(
        input_xml.read_bytes(),
        cert=cert,
        signer=signer,
        signing_time=signing_time,
        timestamper=timestamper,
    )
    _atomic_write_bytes(output_xml, signed)


def _sign_one_cms(
    *,
    input_file: Path,
    output_p7s: Path,
    pkcs11_signer: "PKCS11Signer",
    timestamper,
    overwrite: bool,
) -> None:
    """Sign a single file as a detached CAdES-BES ``.p7s``. Raises on any error."""
    if input_file.resolve() == output_p7s.resolve():
        raise RuntimeError(
            f"Input and output are the same file: {output_p7s}. "
            "Choose a different output path (in batch mode, adjust --output-dir or --suffix)."
        )
    if output_p7s.exists() and not overwrite:
        raise OutputExistsError(
            f"Output file already exists: {output_p7s}\n"
            "Use --overwrite to overwrite it.",
            path=output_p7s,
        )
    ensure_output_parent(output_p7s)
    with input_file.open("rb") as f:
        p7s = sign_cms_detached(f, signer=pkcs11_signer, timestamper=timestamper)
    _atomic_write_bytes(output_p7s, p7s)


def _check_post_sign(result) -> None:
    """Raise if a post-sign verification result has any failed check."""
    failed = [c for c in result.checks if not c.ok]
    if failed:
        detail = "; ".join(c.name + (f" ({c.detail})" if c.detail else "") for c in failed)
        raise RuntimeError(
            f"post-sign verification failed (the produced signature is not intact): {detail}"
        )


def _verify_after_pdf(output_pdf: Path) -> None:
    # Only the signature we just appended (the last one); integrity + coverage, no trust.
    _check_post_sign(verify_pdf(output_pdf, trust_roots=None)[-1])


def _verify_after_xml(output_xml: Path) -> None:
    # Only the signature we just appended (the last one); integrity, no trust.
    _check_post_sign(verify_xml(output_xml.read_bytes(), trust_roots=None)[-1])


def _verify_after_cms(input_file: Path, output_p7s: Path) -> None:
    with input_file.open("rb") as data:
        _check_post_sign(verify_cms(data, output_p7s.read_bytes(), trust_roots=None))


def _detect_input_kind(path: Path) -> str:
    """Detect an UNSIGNED input file's kind for signing: "pdf", "xml" or "any" (arbitrary -> CAdES).

    Mirrors _detect_signature_kind's magic-byte logic, but the fallback is "any" (sign arbitrary
    bytes as a detached CAdES .p7s) instead of attempting a CMS parse. An empty file is "any"."""
    with path.open("rb") as f:
        start = f.read(1024).lstrip(b"\xef\xbb\xbf").lstrip()
    if start[:1] == b"<":
        return "xml"
    if start.startswith(b"%PDF-"):
        return "pdf"
    return "any"


def _resolve_sign_kind(path: Path, sign_as: SignAs) -> str:
    """Resolve the signature kind ("pdf" | "xml" | "any") for an input, honoring --as.

    With SignAs.auto the kind is detected by content; otherwise the requested type is forced
    (cades -> "any", the detached CAdES signer)."""
    if sign_as is SignAs.auto:
        return _detect_input_kind(path)
    return {SignAs.pdf: "pdf", SignAs.xml: "xml", SignAs.cades: "any"}[sign_as]
