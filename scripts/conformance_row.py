#!/usr/bin/env python3
# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""Turn one locally verified signature into one redacted conformance row.

Gaps 1 and 2 of docs/security-invariants.md close with variety, not with code: certificates
issued in different years, cards of both chip generations, signatures that aged into revocation.
No single signer holds those, and a corpus of real signed documents cannot be collected at all,
because a signature file carries the signer's name, their document number and their certificate.
What can be collected is verdicts. This script verifies a signed file locally, extracts only
what identifies the infrastructure, and prints one markdown row to paste into a GitHub issue,
next to the verdict firma.gub.uy gave the same file.

The redaction contract, enforced below rather than promised: a row may never carry the direct
identifiers the verifier saw, the signer's name, their document number, the certificate serial,
the file's name. Redacted is not anonymous, and the protocol says so: what the row keeps is
coarse on purpose. What it does contain is public infrastructure: the
issuing CA's name, which CRL the certificate points at, the algorithm, the TSA's name, and the
two verdicts. If the assembled row is found carrying any of the signer fields the verifier saw,
the script refuses to print it and exits 3, because a redaction that fails should fail loudly.

Usage, in the order the protocol suggests:

    uv run scripts/conformance_row.py firmado.pdf
    # upload the same file at https://firma.gub.uy/ and read its answer, then:
    uv run scripts/conformance_row.py firmado.pdf --firma-gub-uy "correcta"
    # and a second row with revocation consulted:
    uv run scripts/conformance_row.py firmado.pdf --check-revocation --firma-gub-uy "correcta"

Exit codes: 0 row printed, 2 the file could not be verified or its certificate not read, 3 the
redaction guard refused the row.
"""

from __future__ import annotations

import argparse
import base64
import sys
from datetime import datetime
from pathlib import Path

from asn1crypto import cms as asn1cms
from asn1crypto import x509 as asn1x509

# firma.gub.uy's own three answers, taken verbatim from the portal's interface text
# (measured 2026-08-05). People paste whichever they saw, in whatever casing.
_PORTAL_OK = "la firma del documento es correcta"
_PORTAL_BAD = "la firma del documento no es correcta"
_PORTAL_ERR = "se encontró un problema al analizar el documento"


def _sniff(path: Path) -> str:
    head = path.read_bytes()[:1024]
    if head.startswith(b"%PDF"):
        return "pades"
    if head.lstrip(b"\xef\xbb\xbf \t\r\n").startswith(b"<"):
        return "xades"
    return "cades"


def _certificates(path: Path, kind: str) -> list[asn1x509.Certificate]:
    """Every certificate the signature carries, in whatever order the format keeps them."""
    if kind == "cades":
        info = asn1cms.ContentInfo.load(path.read_bytes())
        return [choice.chosen for choice in info["content"]["certificates"] or []]
    if kind == "pades":
        from pyhanko.pdf_utils.reader import PdfFileReader

        with path.open("rb") as handle:
            reader = PdfFileReader(handle)
            return [sig.signer_cert for sig in reader.embedded_signatures if sig.signer_cert]
    from lxml import etree

    tree = etree.fromstring(path.read_bytes())
    return [asn1x509.Certificate.load(base64.b64decode(node.text))
            for node in tree.iter("{http://www.w3.org/2000/09/xmldsig#}X509Certificate")
            if node.text]


def _signer_cert(certs: list[asn1x509.Certificate],
                 common_name: str) -> asn1x509.Certificate | None:
    """The end-entity certificate: the one naming the report's signer, or the one nobody issued."""
    for cert in certs:
        if cert.subject.native.get("common_name", "") == common_name:
            return cert
    issuers = {cert.subject.sha256 for cert in certs if cert.ca}
    for cert in certs:
        if cert.subject.sha256 not in issuers:
            return cert
    return certs[0] if certs else None


def _crl_url(cert: asn1x509.Certificate) -> str:
    try:
        points = cert.crl_distribution_points_value or []
        for point in points:
            for value in _flat(point.native):
                if isinstance(value, str) and value.startswith("http"):
                    return value
    except (ValueError, KeyError):
        pass
    return "none"


def _flat(value):
    if isinstance(value, dict):
        for inner in value.values():
            yield from _flat(inner)
    elif isinstance(value, (list, tuple)):
        for inner in value:
            yield from _flat(inner)
    else:
        yield value


def _portal(raw: str) -> str:
    """The portal's answer as one of its three phrases, or verbatim when it said something else."""
    norm = raw.strip().strip(".").lower()
    if norm in ("", "pending"):
        return "pending"
    if "correcta" in norm and ("no " in norm or norm.startswith("no")):
        return "no correcta"
    if "correcta" in norm or norm in ("valid", "valida", "válida"):
        return "correcta"
    if "problema" in norm or "analizar" in norm or "error" in norm:
        return "problema"
    return " ".join(raw.split())[:60]


def _agree(firmauy: str, portal: str) -> str:
    if firmauy == "VALID" and portal == "correcta":
        return "yes"
    if firmauy == "INVALID" and portal == "no correcta":
        return "yes"
    if (firmauy, portal) in (("VALID", "no correcta"), ("INVALID", "correcta")):
        return "NO"
    return "?"


def _cell(value: object) -> str:
    """One table cell: whitespace collapsed and pipes escaped, because every value here is either
    somebody's pasted text or a field read out of a hostile file, and either can carry the one
    character that breaks a markdown table into wrong columns."""
    return " ".join(str(value).split()).replace("|", "\\|")


def _leaks(row: str, forbidden: dict[str, str]) -> list[str]:
    """Which forbidden values made it into the row. Empty is the only acceptable answer.

    Values shorter than four characters are not checked: a test certificate's serial of "1"
    substring-matches every date and version on the row, and a value that short identifies
    nobody. Real cédula serials, names and document numbers are all comfortably longer.
    """
    found = []
    lowered = row.lower()
    for what, value in forbidden.items():
        value = (value or "").strip().lower()
        if len(value) >= 4 and value in lowered:
            found.append(what)
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("file", type=Path, help="the signed file, verified locally")
    parser.add_argument("--original", type=Path, default=None,
                        help="for a detached .p7s, the file it signs")
    parser.add_argument("--firma-gub-uy", default="pending",
                        help="the phrase the portal showed for the same file, quoted")
    parser.add_argument("--check-revocation", action="store_true",
                        help="consult CRL/OCSP in the local verification (the cédula CRL is large)")
    parser.add_argument("--chip", choices=("v4", "v5"), default=None,
                        help="the card's applet generation, if you know it")
    args = parser.parse_args()

    from firmauy.api import verify

    try:
        report = verify(args.file, original=args.original,
                        check_revocation=args.check_revocation)
    except Exception as exc:
        print(f"could not verify {args.file.name}: {exc}", file=sys.stderr)
        return 2

    if not report.signatures:
        print("the file carries no signatures, so there is nothing to report", file=sys.stderr)
        return 2

    signature = report.signatures[-1]        # the newest, matching the post-sign habit
    kind = _sniff(args.file)
    try:
        cert = _signer_cert(_certificates(args.file, kind),
                            signature.signer.get("common_name", ""))
    except Exception as exc:
        print(f"could not read the certificates out of {args.file.name}: {exc}", file=sys.stderr)
        return 2
    if cert is None:
        print("the signature carries no certificate to describe", file=sys.stderr)
        return 2

    stamp = signature.timestamp
    portal = _portal(args.firma_gub_uy)
    from importlib.metadata import PackageNotFoundError, version
    try:
        firmauy_version = version("firmauy")
    except PackageNotFoundError:
        firmauy_version = "source"

    row = "| " + " | ".join(_cell(value) for value in [
        datetime.now().strftime("%Y-%m"),
        firmauy_version,
        kind,
        str(len(report.signatures)),
        args.chip or "?",
        str(cert["tbs_certificate"]["validity"]["not_before"].native.year),
        cert.issuer.native.get("common_name", "?"),
        _crl_url(cert),
        str(cert["signature_algorithm"]["algorithm"].native),
        (stamp.tsa_common_name or "present") if stamp and stamp.present else "none",
        "yes" if args.check_revocation else "no",
        report.indication,
        portal,
        _agree(report.indication, portal),
    ]) + " |"

    header = ("| date | firmauy | format | sigs | chip | cert issued | issuer | crl | algorithm"
              " | tsa | revocation | firmauy verdict | firma.gub.uy | agree |")

    # The contract, enforced. Everything the verifier learned about the person must be absent
    # from what gets pasted into a public issue, and a redaction that fails must fail loudly.
    forbidden = {
        "signer name": signature.signer.get("common_name", ""),
        "document number": signature.signer.get("serial_number", ""),
        "certificate serial": signature.signer.get("certificate_serial", ""),
        "file name": args.file.name,
    }
    leaked = _leaks(row, forbidden)
    if leaked:
        print(f"refusing to print the row: it carries {', '.join(leaked)}", file=sys.stderr)
        return 3

    print(header)
    print("|" + "|".join(["---"] * (header.count("|") - 1)) + "|")
    print(row)
    print()
    print("Left out on purpose: the signer's name, their document number, the certificate")
    print("serial, the file's name. Paste the three lines above into a GitHub issue titled")
    print('"Conformance row" at https://github.com/carlosplanchon/firmauy/issues')
    if portal == "pending":
        print()
        print("The portal verdict is pending: upload the same file at https://firma.gub.uy/")
        print("and run this again with --firma-gub-uy and the phrase it shows.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
