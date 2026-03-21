from pathlib import Path

from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen import canvas

from cedula_uy_pdf_sign.constants import (
    APPEARANCE_WIDTH,
    APPEARANCE_HEIGHT,
    STAMP_FONT_NAME,
    STAMP_FONT_SIZE,
    STAMP_LEADING,
    STAMP_TEXT_X,
    STAMP_TEXT_Y,
)


def wrap_line(
    text: str,
    font_name: str,
    font_size: float,
    max_width: float,
) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current = ""

    for word in words:
        candidate = word if not current else f"{current} {word}"
        if stringWidth(candidate, font_name, font_size) <= max_width:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word

    if current:
        lines.append(current)

    return lines


def split_signer_name(signer: str) -> list[str]:
    prefix = "Firmado por: "
    max_width = APPEARANCE_WIDTH - STAMP_TEXT_X - 2

    full = f"{prefix}{signer}"
    if stringWidth(full, STAMP_FONT_NAME, STAMP_FONT_SIZE) <= max_width:
        return [full]

    words = signer.split()
    current = prefix
    used_words = 0

    for i, word in enumerate(words):
        candidate = current + word if current.endswith(": ") else f"{current} {word}"
        if stringWidth(candidate, STAMP_FONT_NAME, STAMP_FONT_SIZE) <= max_width:
            current = candidate
            used_words = i + 1
        else:
            break

    remaining = " ".join(words[used_words:]).strip()

    lines = [current]
    if remaining:
        lines.append(remaining)

    return lines


def make_appearance_pdf(
    path: str,
    signer: str,
    cert_serial: str,
    ts: str,
    issuer: str,
) -> None:
    """Render the signature appearance as a ReportLab PDF file."""
    width, height = APPEARANCE_WIDTH, APPEARANCE_HEIGHT

    c = canvas.Canvas(path, pagesize=(width, height))
    c.setPageCompression(0)
    c.setFont(STAMP_FONT_NAME, STAMP_FONT_SIZE)

    signer_lines = split_signer_name(signer)
    issuer_lines = wrap_line(
        issuer,
        STAMP_FONT_NAME,
        STAMP_FONT_SIZE,
        max_width=APPEARANCE_WIDTH - STAMP_TEXT_X - 2,
    )

    lines = [
        "Firma electrónica avanzada, UY",
        *signer_lines,
        f"Documento: {cert_serial}",
        f"Fecha: {ts}",
        *issuer_lines,
    ]

    text = c.beginText(STAMP_TEXT_X, STAMP_TEXT_Y)
    text.setFont(STAMP_FONT_NAME, STAMP_FONT_SIZE)
    text.setLeading(STAMP_LEADING)

    for line in lines:
        text.textLine(line)

    c.drawText(text)
    c.showPage()
    c.save()


def ensure_output_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
