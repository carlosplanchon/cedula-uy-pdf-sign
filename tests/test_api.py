"""Unit tests for the pure (no card, no HSM) parts of the public API firmauy.api.

The card- and PKCS#11-touching API functions are covered by the SoftHSM integration tests
(test_integration_*.py); this file covers the utilities that need no hardware.
"""

from __future__ import annotations

import pytest

from firmauy.api import (
    CaBundle,
    CiReport,
    complete_ci,
    fetch_cas,
    sign,
    sign_files,
    sign_xml,
    validate_ci,
)


def test_validate_ci_accepts_a_consistent_number():
    full = complete_ci("1234567")  # a body turned into a full number with its check digit
    report = validate_ci(full)
    assert isinstance(report, CiReport)
    assert report.valid is True
    assert report.normalized == full
    assert report.body == full[:-1]
    assert report.check_digit == full[-1]
    assert report.expected_check_digit == full[-1]


def test_validate_ci_flags_a_wrong_check_digit():
    full = complete_ci("1234567")
    wrong = full[:-1] + str((int(full[-1]) + 1) % 10)
    report = validate_ci(wrong)
    assert report.valid is False
    assert report.check_digit == wrong[-1]
    assert report.expected_check_digit == full[-1]


def test_validate_ci_rejects_non_digits():
    with pytest.raises(ValueError):
        validate_ci("not-a-number")


def test_complete_ci_appends_a_valid_check_digit():
    full = complete_ci("1111111")
    assert len(full) == 8
    assert validate_ci(full).valid is True


def test_sign_functions_reject_empty_pin(tmp_path):
    """Every signing entry point refuses an empty PIN before touching the card (would spend a retry)."""
    f = tmp_path / "x.txt"
    f.write_text("hola")
    for call in (
        lambda: sign(f, "", native=False),
        lambda: sign_xml(f, "", native=False),
        lambda: sign_files([f], "", native=False),
    ):
        with pytest.raises(ValueError, match="non-empty PIN"):
            call()


def test_fetch_cas_wraps_the_paths_and_cache_dir(monkeypatch, tmp_path):
    import firmauy.national_ca as nca

    root = tmp_path / "acrn.pem"
    intermediate = tmp_path / "mica.pem"
    monkeypatch.setattr(nca, "fetch_cas", lambda progress=None, source_files=None: (root, intermediate))
    monkeypatch.setattr(nca, "cache_dir", lambda: tmp_path)

    bundle = fetch_cas()

    assert isinstance(bundle, CaBundle)
    assert bundle.root_path == root
    assert bundle.intermediate_path == intermediate
    assert bundle.cache_dir == tmp_path


def test_doctor_marks_only_the_token_check_as_sensitive(monkeypatch):
    """The diagnostic contract: every check says whether its detail can carry the cardholder's
    data, so a consumer never has to infer it from the check's name."""
    import firmauy._shared as shared
    from firmauy.api import run_doctor

    raw = [
        {"status": "PASS", "name": "firmauy", "detail": "1.9.0", "fix": None, "sensitive": False},
        {"status": "PASS", "name": "cédula token detected", "detail": "PEREZ PEREZ JUAN",
         "fix": None, "sensitive": True},
    ]
    monkeypatch.setattr(shared, "_collect_doctor_checks", lambda *a, **k: raw)

    checks = run_doctor().checks
    assert [c.sensitive for c in checks] == [False, True]
    # The flag travels on the dataclass, so an API consumer sees the same contract as --json.
    assert checks[1].detail == "PEREZ PEREZ JUAN"


def test_every_collected_check_carries_the_sensitive_flag(monkeypatch):
    """No check may omit the key: a consumer that fails closed on a missing one must never be
    tripped by our own output."""
    import firmauy._shared as shared

    monkeypatch.setattr(shared, "_doctor_pkcs11", lambda add, lib: add(
        "PASS", "cédula token detected", "SOME LABEL", sensitive=True))
    checks = shared._collect_doctor_checks(False, None, "/nonexistent.so")

    assert checks, "expected at least the version and pcscd checks"
    assert all("sensitive" in c for c in checks)
    assert sum(c["sensitive"] for c in checks) == 1     # only the token label


# --- output_path_for (no card, no HSM) --------------------------------------

def test_output_path_for_matches_each_signer_default(tmp_path):
    """The point of the helper is that a caller can warn about an existing output before asking
    for the PIN. If it drifted from where the file actually lands it would be worse than useless.
    """
    from firmauy.api import output_path_for

    pdf = tmp_path / "contrato.pdf"
    pdf.write_bytes(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    xml = tmp_path / "factura.xml"
    xml.write_bytes(b'<?xml version="1.0"?><F/>')
    blob = tmp_path / "datos.bin"
    blob.write_bytes(b"cualquier cosa")

    # Auto-detection, by content: embedded signatures keep the extension, detached ones append.
    assert output_path_for(pdf) == tmp_path / "contrato_firmado.pdf"
    assert output_path_for(xml) == tmp_path / "factura_firmado.xml"
    assert output_path_for(blob) == tmp_path / "datos.bin.p7s"


def test_output_path_for_honours_a_forced_type(tmp_path):
    pdf = tmp_path / "contrato.pdf"
    pdf.write_bytes(b"%PDF-1.7\n")

    from firmauy.api import output_path_for

    # Signing a PDF as a detached .p7s leaves the original bytes untouched, which some
    # counterparties ask for.
    assert output_path_for(pdf, sign_as="cades") == tmp_path / "contrato.pdf.p7s"
    assert output_path_for(pdf, sign_as="pdf") == tmp_path / "contrato_firmado.pdf"


def test_output_path_for_places_a_batch_flat_in_the_output_dir(tmp_path):
    from firmauy.api import output_path_for

    src = tmp_path / "sub"
    src.mkdir()
    blob = src / "datos.bin"
    blob.write_bytes(b"x")
    out = tmp_path / "firmados"

    assert output_path_for(blob, output_dir=out) == out / "datos.bin.p7s"


def test_output_path_for_can_answer_about_a_file_that_is_not_there(tmp_path):
    """With an explicit type nothing is read, so a caller can ask before the file exists."""
    from firmauy.api import output_path_for

    assert output_path_for(tmp_path / "todavia_no.xml",
                           sign_as="xml") == tmp_path / "todavia_no_firmado.xml"


def test_output_path_for_rejects_an_unknown_type(tmp_path):
    from firmauy.api import output_path_for

    with pytest.raises(ValueError):
        output_path_for(tmp_path / "x.pdf", sign_as="pkcs7")
