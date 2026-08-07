# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

from dataclasses import dataclass
from enum import Enum


@dataclass(frozen=True)
class StampFields:
    """Which of the five lines the visible stamp prints.

    One object rather than five booleans threaded through every signing function, which is the
    only reason it exists: the public shape is :class:`firmauy.api.PdfAppearance`, which spells
    them out flat because that is what a checkbox binds to.

    Every line can be turned off, including the signer's name. The stamp is decoration drawn on
    a page, not the signature: whoever verifies the file reads the signer, the issuer and the
    time out of the signature itself, where they are covered by the cryptography and cannot be
    edited away. Turning off ``document`` is worth knowing about for a different reason: it is
    the certificate's serial rather than the cédula number, so it identifies the certificate
    without printing somebody's national ID on every copy of the file.
    """

    title: bool = True       # "Firma electrónica avanzada, UY"
    signer: bool = True      # "Firmado por: ..."
    document: bool = True    # "Documento: ..." (the certificate serial)
    date: bool = True        # "Fecha: ..."
    issuer: bool = True      # the issuing authority's name

    @property
    def any(self) -> bool:
        """False when every line is off, which draws no text block at all."""
        return any((self.title, self.signer, self.document, self.date, self.issuer))


class ImageMode(str, Enum):
    """Where an --image goes inside the signature appearance box."""
    background = "background"   # behind the text (subtle watermark)
    side = "side"               # to the left of the text
    only = "only"               # image only, no text


class SignAs(str, Enum):
    """The signature type for the unified `sign` / `sign-batch` commands."""
    auto = "auto"     # detect by file content: PDF -> pdf, XML -> xml, else -> cades
    pdf = "pdf"       # force PAdES (embedded PDF signature)
    xml = "xml"       # force XAdES (enveloped XML signature)
    cades = "cades"   # force detached CAdES (.p7s), for any input including PDF/XML


# Default opacity for an image in --image-mode background (subtle watermark, keeps text legible).
DEFAULT_IMAGE_OPACITY = 0.2

DEFAULT_PKCS11_LIB = "/usr/lib/pkcs11/libgclib.so"
DEFAULT_TIMEZONE = "America/Montevideo"

# Reference dimensions for the signature field:
# Rect [20 20 225 90] => 205 x 70
APPEARANCE_WIDTH = 205
APPEARANCE_HEIGHT = 70

DEFAULT_X1 = 20
DEFAULT_Y1 = 20
DEFAULT_X2 = DEFAULT_X1 + APPEARANCE_WIDTH   # 225
DEFAULT_Y2 = DEFAULT_Y1 + APPEARANCE_HEIGHT  # 90

# Signature field font values
STAMP_FONT_NAME = "Helvetica"
STAMP_FONT_SIZE = 8.0
STAMP_LEADING = 9.6
STAMP_TEXT_X = 4.0
STAMP_TEXT_Y = 58.0

