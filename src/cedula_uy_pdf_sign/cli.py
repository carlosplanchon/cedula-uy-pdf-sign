#!/usr/bin/env python3

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
        "Firmar PDFs con cédula uruguaya vía PKCS#11 + pyHanko.\n\n"
        "Este proyecto no está afiliado ni cuenta con el respaldo de AGESIC. "
        "No garantiza validez legal. Uselo bajo su propia responsabilidad."
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
            f"El archivo de salida ya existe: {output_pdf}\n"
            "Usa --overwrite para sobreescribirlo."
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
                        f"El campo '{field_name}' ya contiene una firma. "
                        "Usar --force para continuar de todas formas (el PDF podría quedar inválido)."
                    )
                typer.secho(
                    f"Advertencia: el campo '{field_name}' ya contiene una firma. "
                    "Continuando por --force (el PDF podría quedar inválido).",
                    fg=typer.colors.YELLOW,
                    err=True,
                )
            else:
                typer.secho(
                    f"Advertencia: el campo '{field_name}' ya existe pero no está firmado, "
                    "se reutilizará.",
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
        DEFAULT_PKCS11_LIB, "--pkcs11-lib", help="Ruta al módulo PKCS#11.",
    ),
) -> None:
    """List all PKCS#11 tokens visible in the library."""
    try:
        lib = load_pkcs11_lib(pkcs11_lib)
        tokens = list(lib.get_tokens())
        if not tokens:
            typer.echo("No se encontraron tokens PKCS#11.")
            return

        header = f"{'Label':<32}  {'Fabricante':<20}  {'Modelo':<16}  Serial"
        typer.echo(header)
        typer.echo("-" * len(header))
        for token in tokens:
            label = (getattr(token, "label", "") or "").strip() or "<sin label>"
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
        DEFAULT_PKCS11_LIB, "--pkcs11-lib", help="Ruta al módulo PKCS#11.",
    ),
    token_label: Optional[str] = typer.Option(
        None, "--token-label",
        help="Label exacto del token PKCS#11. Si no se indica, se autodetecta.",
    ),
    pin_source: PinSource = typer.Option(
        PinSource.prompt, "--pin-source",
        help="Cómo obtener el PIN: prompt (default), env, stdin, fd.",
    ),
    pin_env_var: Optional[str] = typer.Option(
        None, "--pin-env-var",
        help="Variable de entorno con el PIN (requiere --pin-source env).",
    ),
    pin_fd: Optional[int] = typer.Option(
        None, "--pin-fd",
        help="File descriptor con el PIN (requiere --pin-source fd).",
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
                    digital_sig = "sí" if ku.value.digital_signature else "no"
                except x509.ExtensionNotFound:
                    digital_sig = "?"

                typer.echo(
                    f"ID:            {obj_id.hex()}\n"
                    f"Subject:       {subject_cn}\n"
                    f"Emisor:        {issuer_cn}\n"
                    f"Serial:        {serial}\n"
                    f"Válido hasta:  {not_after}\n"
                    f"Firma digital: {digital_sig}\n"
                )

            if not found:
                typer.echo("No se encontraron certificados en el token.")

    except Exception as exc:
        typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Subcommand: sign
# ---------------------------------------------------------------------------

@app.command()
def sign(
    input_pdf: Path = typer.Argument(..., exists=True, readable=True, help="PDF de entrada."),
    output_pdf: Path = typer.Argument(..., help="PDF de salida firmado."),
    pkcs11_lib: str = typer.Option(
        DEFAULT_PKCS11_LIB, "--pkcs11-lib", help="Ruta al módulo PKCS#11.",
    ),
    token_label: Optional[str] = typer.Option(
        None, "--token-label",
        help="Label exacto del token PKCS#11. Si no se indica, se autodetecta.",
    ),
    cert_id: Optional[str] = typer.Option(
        None, "--cert-id",
        help="ID hexadecimal del certificado/clave PKCS#11. Si no se indica, se autodetecta.",
    ),
    pin_source: PinSource = typer.Option(
        PinSource.prompt, "--pin-source",
        help="Cómo obtener el PIN: prompt (default), env, stdin, fd.",
    ),
    pin_env_var: Optional[str] = typer.Option(
        None, "--pin-env-var",
        help="Variable de entorno con el PIN (requiere --pin-source env).",
    ),
    pin_fd: Optional[int] = typer.Option(
        None, "--pin-fd",
        help="File descriptor con el PIN (requiere --pin-source fd).",
    ),
    field_name: str = typer.Option(
        "Sig1", "--field-name", help="Nombre del campo de firma.",
    ),
    page: int = typer.Option(
        -1, "--page",
        help="Página donde colocar la firma visible. -1 = última página.",
    ),
    x1: int = typer.Option(DEFAULT_X1, "--x1", help="Coordenada X1 del recuadro."),
    y1: int = typer.Option(DEFAULT_Y1, "--y1", help="Coordenada Y1 del recuadro."),
    x2: int = typer.Option(DEFAULT_X2, "--x2", help="Coordenada X2 del recuadro."),
    y2: int = typer.Option(DEFAULT_Y2, "--y2", help="Coordenada Y2 del recuadro."),
    timezone: str = typer.Option(
        DEFAULT_TIMEZONE, "--timezone", help="Zona horaria para el texto visible.",
    ),
    reason: Optional[str] = typer.Option(None, "--reason", help="Motivo de la firma."),
    location: Optional[str] = typer.Option(None, "--location", help="Lugar de la firma."),
    contact_info: Optional[str] = typer.Option(
        None, "--contact-info", help="Contacto del firmante.",
    ),
    tsa_url: Optional[str] = typer.Option(
        None, "--tsa-url",
        help="URL de la autoridad de sellado de tiempo (TSA). Ayuda a preservar evidencia temporal de la firma. No aplica para firma con cédula uruguaya.",
    ),
    overwrite: bool = typer.Option(
        False, "--overwrite", help="Permitir sobreescribir el archivo de salida si ya existe.",
    ),
    force: bool = typer.Option(
        False, "--force",
        help="Continuar aunque el campo de firma ya contenga una firma (el PDF resultante podría quedar inválido).",
    ),
) -> None:
    """Sign a PDF with a Uruguayan cédula via PKCS#11 and pyHanko."""
    try:
        # --- Pre-flight checks ---
        if input_pdf.resolve() == output_pdf.resolve():
            raise RuntimeError(
                "El archivo de entrada y el de salida son el mismo. "
                "Especifica una ruta de salida diferente."
            )

        if output_pdf.exists() and not overwrite:
            raise RuntimeError(
                f"El archivo de salida ya existe: {output_pdf}\n"
                "Usa --overwrite para sobreescribirlo."
            )

        ensure_output_parent(output_pdf)

        if x2 <= x1 or y2 <= y1:
            raise typer.BadParameter(
                "Las coordenadas deben satisfacer x1 < x2 e y1 < y2."
            )

        box_width = x2 - x1
        box_height = y2 - y1
        if box_width != APPEARANCE_WIDTH or box_height != APPEARANCE_HEIGHT:
            typer.secho(
                f"Advertencia: el box de firma ({box_width}x{box_height}) difiere del "
                f"tamaño de referencia ({APPEARANCE_WIDTH}x{APPEARANCE_HEIGHT}). "
                "La apariencia será escalada.",
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

            token_label_display = (getattr(token, "label", "") or "").strip() or "<sin label>"
            typer.echo(f"Token:             {token_label_display}")
            typer.echo(f"Firmante:          {signer_name}")
            typer.echo(f"Emisor:            {issuer_name}")
            typer.echo(f"ID PKCS#11:        {key_id.hex()}")
            typer.echo(f"Serial certificado: {cert_serial}")
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

        typer.secho(f"PDF firmado correctamente: {output_pdf}", fg=typer.colors.GREEN)

    except Exception as exc:
        typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Subcommand: sign-batch
# ---------------------------------------------------------------------------

@app.command("sign-batch")
def sign_batch(
    input_pdfs: Optional[List[Path]] = typer.Argument(None, help="PDFs de entrada a firmar."),
    output_dir: Path = typer.Option(..., "--output-dir", help="Directorio donde guardar los PDFs firmados."),
    suffix: str = typer.Option("_firmado", "--suffix", help="Sufijo que se añade al nombre base del archivo de salida."),
    input_dir: Optional[Path] = typer.Option(
        None, "--input-dir",
        help="Carpeta de PDFs a firmar. Puede combinarse con argumentos individuales.",
    ),
    recursive: bool = typer.Option(
        False, "--recursive",
        help="Buscar PDFs recursivamente en --input-dir.",
    ),
    pkcs11_lib: str = typer.Option(
        DEFAULT_PKCS11_LIB, "--pkcs11-lib", help="Ruta al módulo PKCS#11.",
    ),
    token_label: Optional[str] = typer.Option(
        None, "--token-label",
        help="Label exacto del token PKCS#11. Si no se indica, se autodetecta.",
    ),
    cert_id: Optional[str] = typer.Option(
        None, "--cert-id",
        help="ID hexadecimal del certificado/clave PKCS#11. Si no se indica, se autodetecta.",
    ),
    pin_source: PinSource = typer.Option(
        PinSource.prompt, "--pin-source",
        help="Cómo obtener el PIN: prompt (default), env, stdin, fd.",
    ),
    pin_env_var: Optional[str] = typer.Option(
        None, "--pin-env-var",
        help="Variable de entorno con el PIN (requiere --pin-source env).",
    ),
    pin_fd: Optional[int] = typer.Option(
        None, "--pin-fd",
        help="File descriptor con el PIN (requiere --pin-source fd).",
    ),
    field_name: str = typer.Option(
        "Sig1", "--field-name", help="Nombre del campo de firma.",
    ),
    page: int = typer.Option(
        -1, "--page",
        help="Página donde colocar la firma visible. -1 = última página.",
    ),
    x1: int = typer.Option(DEFAULT_X1, "--x1", help="Coordenada X1 del recuadro."),
    y1: int = typer.Option(DEFAULT_Y1, "--y1", help="Coordenada Y1 del recuadro."),
    x2: int = typer.Option(DEFAULT_X2, "--x2", help="Coordenada X2 del recuadro."),
    y2: int = typer.Option(DEFAULT_Y2, "--y2", help="Coordenada Y2 del recuadro."),
    timezone: str = typer.Option(
        DEFAULT_TIMEZONE, "--timezone", help="Zona horaria para el texto visible.",
    ),
    reason: Optional[str] = typer.Option(None, "--reason", help="Motivo de la firma."),
    location: Optional[str] = typer.Option(None, "--location", help="Lugar de la firma."),
    contact_info: Optional[str] = typer.Option(
        None, "--contact-info", help="Contacto del firmante.",
    ),
    tsa_url: Optional[str] = typer.Option(
        None, "--tsa-url",
        help="URL de la autoridad de sellado de tiempo (TSA). No aplica para firma con cédula uruguaya.",
    ),
    overwrite: bool = typer.Option(
        False, "--overwrite", help="Permitir sobreescribir archivos de salida si ya existen.",
    ),
    force: bool = typer.Option(
        False, "--force",
        help="Continuar aunque el campo de firma ya contenga una firma.",
    ),
) -> None:
    """Sign multiple PDFs with a single PKCS#11 session (batch mode)."""
    try:
        all_pdfs: List[Path] = list(input_pdfs) if input_pdfs else []

        if input_dir is not None:
            if not input_dir.is_dir():
                typer.secho(
                    f"--input-dir '{input_dir}' no es un directorio válido.",
                    fg=typer.colors.RED,
                    err=True,
                )
                raise typer.Exit(code=1)
            pattern = "**/*.pdf" if recursive else "*.pdf"
            all_pdfs += sorted(input_dir.glob(pattern))

        if not all_pdfs:
            typer.secho(
                "No se especificaron archivos de entrada. "
                "Usa argumentos posicionales o --input-dir.",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)

        input_pdfs = all_pdfs

        if x2 <= x1 or y2 <= y1:
            typer.secho(
                "Las coordenadas deben satisfacer x1 < x2 e y1 < y2.",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)

        box_width = x2 - x1
        box_height = y2 - y1
        if box_width != APPEARANCE_WIDTH or box_height != APPEARANCE_HEIGHT:
            typer.secho(
                f"Advertencia: el box de firma ({box_width}x{box_height}) difiere del "
                f"tamaño de referencia ({APPEARANCE_WIDTH}x{APPEARANCE_HEIGHT}). "
                "La apariencia será escalada.",
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

            token_label_display = (getattr(token, "label", "") or "").strip() or "<sin label>"
            typer.echo(f"Token:              {token_label_display}")
            typer.echo(f"Firmante:           {signer_name}")
            typer.echo(f"Emisor:             {issuer_name}")
            typer.echo(f"ID PKCS#11:         {key_id.hex()}")
            typer.echo(f"Serial certificado: {cert_serial}")
            if tsa_url:
                typer.echo(f"TSA:                {tsa_url}")
            typer.echo(f"Archivos a firmar:  {len(input_pdfs)}")
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
        typer.echo(f"Firmados: {ok_count}/{len(input_pdfs)}. Errores: {err_count}.")

        if err_count:
            raise typer.Exit(code=1)

    except typer.Exit:
        raise
    except Exception as exc:
        typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
