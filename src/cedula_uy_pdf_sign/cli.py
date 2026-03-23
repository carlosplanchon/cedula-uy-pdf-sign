#!/usr/bin/env python3
# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

import tempfile
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from zoneinfo import ZoneInfo

import pkcs11
import typer
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

from cedula_uy_pdf_sign.appearance import ensure_output_parent, make_appearance_pdf
from cedula_uy_pdf_sign.cert_utils import get_common_name, normalize_issuer_name, cert_not_after
from cedula_uy_pdf_sign.constants import (
    APPEARANCE_HEIGHT,
    APPEARANCE_WIDTH,
    DEFAULT_PKCS11_LIB,
    DEFAULT_TIMEZONE,
    DEFAULT_X1,
    DEFAULT_X2,
    DEFAULT_Y1,
    DEFAULT_Y2,
)
from cedula_uy_pdf_sign.pin import PinSource, get_pin
from cedula_uy_pdf_sign.pkcs11_utils import (
    find_token,
    iter_cert_objects,
    load_pkcs11_lib,
    select_certificate,
)

app = typer.Typer(
    help=(
        "Sign PDFs with Uruguayan ID card via PKCS#11 + pyHanko.\n\n"
        "Runs locally by default: no data is transmitted externally.\n"
        "(Note: TSA usage may involve external connections depending on configuration.)\n\n"
        "This project is not affiliated with or endorsed by AGESIC. "
        "No legal validity guaranteed. Use at your own risk."
    )
)


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

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
) -> None:
    """Sign a single PDF. Raises on any error."""
    if output_pdf.exists() and not overwrite:
        raise RuntimeError(
            f"Output file already exists: {output_pdf}\n"
            "Use --overwrite to overwrite it."
        )

    ensure_output_parent(output_pdf)

    with input_pdf.open("rb") as inf:
        writer = IncrementalPdfFileWriter(inf)

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
                typer.secho(
                    f"Warning: field '{field_name}' already contains a signature. "
                    "Continuing due to --force (the PDF may become invalid).",
                    fg=typer.colors.YELLOW,
                    err=True,
                )
            else:
                typer.secho(
                    f"Warning: field '{field_name}' already exists but is unsigned, "
                    "it will be reused.",
                    fg=typer.colors.YELLOW,
                    err=True,
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

            with output_pdf.open("wb") as outf:
                pdf_signer.sign_pdf(writer, output=outf)

        finally:
            if appearance_path:
                try:
                    Path(appearance_path).unlink(missing_ok=True)
                except Exception:
                    pass


# ---------------------------------------------------------------------------
# Subcommand: list-tokens
# ---------------------------------------------------------------------------

@app.command("list-tokens")
def list_tokens(
    pkcs11_lib: str = typer.Option(
        DEFAULT_PKCS11_LIB, "--pkcs11-lib", help="Path to the PKCS#11 module.",
    ),
) -> None:
    """List all PKCS#11 tokens visible in the library."""
    try:
        lib = load_pkcs11_lib(pkcs11_lib)
        tokens = list(lib.get_tokens())
        if not tokens:
            typer.echo("No PKCS#11 tokens found.")
            return

        header = f"{'Label':<32}  {'Manufacturer':<20}  {'Model':<16}  Serial"
        typer.echo(header)
        typer.echo("-" * len(header))
        for token in tokens:
            label = (getattr(token, "label", "") or "").strip() or "<no label>"
            manufacturer = (getattr(token, "manufacturer", "") or "").strip() or "-"
            model = (getattr(token, "model", "") or "").strip() or "-"
            serial = (getattr(token, "serial", "") or "").strip() or "-"
            typer.echo(f"{label:<32}  {manufacturer:<20}  {model:<16}  {serial}")

    except Exception as exc:
        typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Subcommand: list-certs
# ---------------------------------------------------------------------------

@app.command("list-certs")
def list_certs(
    pkcs11_lib: str = typer.Option(
        DEFAULT_PKCS11_LIB, "--pkcs11-lib", help="Path to the PKCS#11 module.",
    ),
    token_label: Optional[str] = typer.Option(
        None, "--token-label",
        help="Exact PKCS#11 token label. If not provided, auto-detected.",
    ),
    pin_source: PinSource = typer.Option(
        PinSource.prompt, "--pin-source",
        help="How to obtain the PIN: prompt (default), env, stdin, fd.",
    ),
    pin_env_var: Optional[str] = typer.Option(
        None, "--pin-env-var",
        help="Environment variable holding the PIN (requires --pin-source env).",
    ),
    pin_fd: Optional[int] = typer.Option(
        None, "--pin-fd",
        help="File descriptor holding the PIN (requires --pin-source fd).",
    ),
) -> None:
    """List all certificates available on the token."""
    try:
        lib = load_pkcs11_lib(pkcs11_lib)
        token = find_token(lib, token_label)
        final_pin = get_pin(pin_source, pin_env_var, pin_fd)

        with token.open(user_pin=final_pin) as session:
            found = False
            for cert_obj in iter_cert_objects(session):
                try:
                    obj_id = cert_obj[pkcs11.Attribute.ID]
                    cert_der = cert_obj[pkcs11.Attribute.VALUE]
                    cert = x509.load_der_x509_certificate(cert_der)
                except Exception:
                    continue

                found = True
                subject_cn = get_common_name(cert.subject)
                issuer_cn = normalize_issuer_name(get_common_name(cert.issuer))
                serial = format(cert.serial_number, "X")
                not_after = cert_not_after(cert)
                try:
                    ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
                    digital_sig = "yes" if ku.value.digital_signature else "no"
                except x509.ExtensionNotFound:
                    digital_sig = "?"

                typer.echo(
                    f"ID:                {obj_id.hex()}\n"
                    f"Subject:           {subject_cn}\n"
                    f"Issuer:            {issuer_cn}\n"
                    f"Serial:            {serial}\n"
                    f"Valid until:       {not_after}\n"
                    f"Digital signature: {digital_sig}\n"
                )

            if not found:
                typer.echo("No certificates found in the token.")

    except Exception as exc:
        typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Subcommand: sign
# ---------------------------------------------------------------------------

@app.command()
def sign(
    input_pdf: Path = typer.Argument(..., exists=True, readable=True, help="Input PDF."),
    output_pdf: Path = typer.Argument(..., help="Signed output PDF."),
    pkcs11_lib: str = typer.Option(
        DEFAULT_PKCS11_LIB, "--pkcs11-lib", help="Path to the PKCS#11 module.",
    ),
    token_label: Optional[str] = typer.Option(
        None, "--token-label",
        help="Exact PKCS#11 token label. If not provided, auto-detected.",
    ),
    cert_id: Optional[str] = typer.Option(
        None, "--cert-id",
        help="Hexadecimal ID of the PKCS#11 certificate/key. If not provided, auto-detected.",
    ),
    pin_source: PinSource = typer.Option(
        PinSource.prompt, "--pin-source",
        help="How to obtain the PIN: prompt (default), env, stdin, fd.",
    ),
    pin_env_var: Optional[str] = typer.Option(
        None, "--pin-env-var",
        help="Environment variable holding the PIN (requires --pin-source env).",
    ),
    pin_fd: Optional[int] = typer.Option(
        None, "--pin-fd",
        help="File descriptor holding the PIN (requires --pin-source fd).",
    ),
    field_name: str = typer.Option(
        "Sig1", "--field-name", help="Signature field name.",
    ),
    page: int = typer.Option(
        -1, "--page",
        help="Page where the visible signature is placed. -1 = last page.",
    ),
    x1: int = typer.Option(DEFAULT_X1, "--x1", help="X1 coordinate of the signature box."),
    y1: int = typer.Option(DEFAULT_Y1, "--y1", help="Y1 coordinate of the signature box."),
    x2: int = typer.Option(DEFAULT_X2, "--x2", help="X2 coordinate of the signature box."),
    y2: int = typer.Option(DEFAULT_Y2, "--y2", help="Y2 coordinate of the signature box."),
    timezone: str = typer.Option(
        DEFAULT_TIMEZONE, "--timezone", help="Timezone for the visible timestamp.",
    ),
    reason: Optional[str] = typer.Option(None, "--reason", help="Reason for signing."),
    location: Optional[str] = typer.Option(None, "--location", help="Location of signing."),
    contact_info: Optional[str] = typer.Option(
        None, "--contact-info", help="Signer contact information.",
    ),
    tsa_url: Optional[str] = typer.Option(
        None, "--tsa-url",
        help="URL of the Time Stamping Authority (TSA). Helps preserve temporal evidence of the signature. Not applicable for Uruguayan cédula signatures.",
    ),
    overwrite: bool = typer.Option(
        False, "--overwrite", help="Allow overwriting the output file if it already exists.",
    ),
    force: bool = typer.Option(
        False, "--force",
        help="Continue even if the signature field already contains a signature (the resulting PDF may become invalid).",
    ),
) -> None:
    """Sign a PDF with a Uruguayan cédula via PKCS#11 and pyHanko."""
    try:
        # --- Pre-flight checks ---
        if input_pdf.resolve() == output_pdf.resolve():
            raise RuntimeError(
                "Input and output files are the same. "
                "Specify a different output path."
            )

        if output_pdf.exists() and not overwrite:
            raise RuntimeError(
                f"Output file already exists: {output_pdf}\n"
                "Use --overwrite to overwrite it."
            )

        ensure_output_parent(output_pdf)

        if x2 <= x1 or y2 <= y1:
            raise typer.BadParameter(
                "Coordinates must satisfy x1 < x2 and y1 < y2."
            )

        box_width = x2 - x1
        box_height = y2 - y1
        if box_width != APPEARANCE_WIDTH or box_height != APPEARANCE_HEIGHT:
            typer.secho(
                f"Warning: signature box ({box_width}x{box_height}) differs from "
                f"the reference size ({APPEARANCE_WIDTH}x{APPEARANCE_HEIGHT}). "
                "The appearance will be scaled.",
                fg=typer.colors.YELLOW,
                err=True,
            )

        final_pin = get_pin(pin_source, pin_env_var, pin_fd)

        lib = load_pkcs11_lib(pkcs11_lib)
        token = find_token(lib, token_label)

        with token.open(user_pin=final_pin) as session:
            key_id, cert = select_certificate(session, cert_id)

            signer_name = get_common_name(cert.subject)
            issuer_name = normalize_issuer_name(get_common_name(cert.issuer))
            cert_serial = format(cert.serial_number, "X")

            token_label_display = (getattr(token, "label", "") or "").strip() or "<no label>"
            typer.echo(f"Token:               {token_label_display}")
            typer.echo(f"Signer:              {signer_name}")
            typer.echo(f"Issuer:              {issuer_name}")
            typer.echo(f"PKCS#11 ID:          {key_id.hex()}")
            typer.echo(f"Certificate serial:  {cert_serial}")
            if tsa_url:
                typer.echo(f"TSA:               {tsa_url}")

            pkcs11_signer = PKCS11Signer(
                pkcs11_session=session,
                cert_id=key_id,
                key_id=key_id,
            )

            timestamper = HTTPTimeStamper(tsa_url) if tsa_url else None

            meta = signers.PdfSignatureMetadata(
                field_name=field_name,
                reason=reason,
                location=location,
                contact_info=contact_info,
                md_algorithm=None,
            )

            _sign_one_pdf(
                input_pdf=input_pdf,
                output_pdf=output_pdf,
                pkcs11_signer=pkcs11_signer,
                signer_name=signer_name,
                issuer_name=issuer_name,
                cert_serial=cert_serial,
                timestamper=timestamper,
                meta=meta,
                page=page,
                x1=x1,
                y1=y1,
                x2=x2,
                y2=y2,
                timezone=timezone,
                field_name=field_name,
                force=force,
                overwrite=overwrite,
            )

        typer.secho(f"PDF signed successfully: {output_pdf}", fg=typer.colors.GREEN)

    except Exception as exc:
        typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Subcommand: sign-batch
# ---------------------------------------------------------------------------

@app.command("sign-batch")
def sign_batch(
    input_pdfs: Optional[List[Path]] = typer.Argument(None, help="Input PDFs to sign."),
    output_dir: Path = typer.Option(..., "--output-dir", help="Directory where signed PDFs will be saved."),
    suffix: str = typer.Option("_firmado", "--suffix", help="Suffix appended to the base name of each output file."),
    input_dir: Optional[Path] = typer.Option(
        None, "--input-dir",
        help="Folder of PDFs to sign. Can be combined with positional arguments.",
    ),
    recursive: bool = typer.Option(
        False, "--recursive",
        help="Recursively search for PDFs in --input-dir.",
    ),
    pkcs11_lib: str = typer.Option(
        DEFAULT_PKCS11_LIB, "--pkcs11-lib", help="Path to the PKCS#11 module.",
    ),
    token_label: Optional[str] = typer.Option(
        None, "--token-label",
        help="Exact PKCS#11 token label. If not provided, auto-detected.",
    ),
    cert_id: Optional[str] = typer.Option(
        None, "--cert-id",
        help="Hexadecimal ID of the PKCS#11 certificate/key. If not provided, auto-detected.",
    ),
    pin_source: PinSource = typer.Option(
        PinSource.prompt, "--pin-source",
        help="How to obtain the PIN: prompt (default), env, stdin, fd.",
    ),
    pin_env_var: Optional[str] = typer.Option(
        None, "--pin-env-var",
        help="Environment variable holding the PIN (requires --pin-source env).",
    ),
    pin_fd: Optional[int] = typer.Option(
        None, "--pin-fd",
        help="File descriptor holding the PIN (requires --pin-source fd).",
    ),
    field_name: str = typer.Option(
        "Sig1", "--field-name", help="Signature field name.",
    ),
    page: int = typer.Option(
        -1, "--page",
        help="Page where the visible signature is placed. -1 = last page.",
    ),
    x1: int = typer.Option(DEFAULT_X1, "--x1", help="X1 coordinate of the signature box."),
    y1: int = typer.Option(DEFAULT_Y1, "--y1", help="Y1 coordinate of the signature box."),
    x2: int = typer.Option(DEFAULT_X2, "--x2", help="X2 coordinate of the signature box."),
    y2: int = typer.Option(DEFAULT_Y2, "--y2", help="Y2 coordinate of the signature box."),
    timezone: str = typer.Option(
        DEFAULT_TIMEZONE, "--timezone", help="Timezone for the visible timestamp.",
    ),
    reason: Optional[str] = typer.Option(None, "--reason", help="Reason for signing."),
    location: Optional[str] = typer.Option(None, "--location", help="Location of signing."),
    contact_info: Optional[str] = typer.Option(
        None, "--contact-info", help="Signer contact information.",
    ),
    tsa_url: Optional[str] = typer.Option(
        None, "--tsa-url",
        help="URL of the Time Stamping Authority (TSA). Not applicable for Uruguayan cédula signatures.",
    ),
    overwrite: bool = typer.Option(
        False, "--overwrite", help="Allow overwriting output files if they already exist.",
    ),
    force: bool = typer.Option(
        False, "--force",
        help="Continue even if the signature field already contains a signature.",
    ),
) -> None:
    """Sign multiple PDFs with a single PKCS#11 session (batch mode)."""
    try:
        all_pdfs: List[Path] = list(input_pdfs) if input_pdfs else []

        if input_dir is not None:
            if not input_dir.is_dir():
                typer.secho(
                    f"--input-dir '{input_dir}' is not a valid directory.",
                    fg=typer.colors.RED,
                    err=True,
                )
                raise typer.Exit(code=1)
            pattern = "**/*.pdf" if recursive else "*.pdf"
            all_pdfs += sorted(input_dir.glob(pattern))

        if not all_pdfs:
            typer.secho(
                "No input files specified. "
                "Use positional arguments or --input-dir.",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)

        input_pdfs = all_pdfs

        if x2 <= x1 or y2 <= y1:
            typer.secho(
                "Coordinates must satisfy x1 < x2 and y1 < y2.",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)

        box_width = x2 - x1
        box_height = y2 - y1
        if box_width != APPEARANCE_WIDTH or box_height != APPEARANCE_HEIGHT:
            typer.secho(
                f"Warning: signature box ({box_width}x{box_height}) differs from "
                f"the reference size ({APPEARANCE_WIDTH}x{APPEARANCE_HEIGHT}). "
                "The appearance will be scaled.",
                fg=typer.colors.YELLOW,
                err=True,
            )

        output_dir.mkdir(parents=True, exist_ok=True)

        final_pin = get_pin(pin_source, pin_env_var, pin_fd)

        lib = load_pkcs11_lib(pkcs11_lib)
        token = find_token(lib, token_label)

        with token.open(user_pin=final_pin) as session:
            key_id, cert = select_certificate(session, cert_id)

            signer_name = get_common_name(cert.subject)
            issuer_name = normalize_issuer_name(get_common_name(cert.issuer))
            cert_serial = format(cert.serial_number, "X")

            token_label_display = (getattr(token, "label", "") or "").strip() or "<no label>"
            typer.echo(f"Token:               {token_label_display}")
            typer.echo(f"Signer:              {signer_name}")
            typer.echo(f"Issuer:              {issuer_name}")
            typer.echo(f"PKCS#11 ID:          {key_id.hex()}")
            typer.echo(f"Certificate serial:  {cert_serial}")
            if tsa_url:
                typer.echo(f"TSA:                 {tsa_url}")
            typer.echo(f"Files to sign:       {len(input_pdfs)}")
            typer.echo("")

            pkcs11_signer = PKCS11Signer(
                pkcs11_session=session,
                cert_id=key_id,
                key_id=key_id,
            )

            timestamper = HTTPTimeStamper(tsa_url) if tsa_url else None

            meta = signers.PdfSignatureMetadata(
                field_name=field_name,
                reason=reason,
                location=location,
                contact_info=contact_info,
                md_algorithm=None,
            )

            ok_count = 0
            err_count = 0

            for input_pdf in input_pdfs:
                output_pdf = output_dir / f"{input_pdf.stem}{suffix}.pdf"
                try:
                    _sign_one_pdf(
                        input_pdf=input_pdf,
                        output_pdf=output_pdf,
                        pkcs11_signer=pkcs11_signer,
                        signer_name=signer_name,
                        issuer_name=issuer_name,
                        cert_serial=cert_serial,
                        timestamper=timestamper,
                        meta=meta,
                        page=page,
                        x1=x1,
                        y1=y1,
                        x2=x2,
                        y2=y2,
                        timezone=timezone,
                        field_name=field_name,
                        force=force,
                        overwrite=overwrite,
                    )
                    typer.secho(f"OK:    {output_pdf}", fg=typer.colors.GREEN)
                    ok_count += 1
                except Exception as exc:
                    typer.secho(f"ERROR: {input_pdf}: {exc}", fg=typer.colors.RED, err=True)
                    err_count += 1

        typer.echo("")
        typer.echo(f"Signed: {ok_count}/{len(input_pdfs)}. Errors: {err_count}.")

        if err_count:
            raise typer.Exit(code=1)

    except typer.Exit:
        raise
    except Exception as exc:
        typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
