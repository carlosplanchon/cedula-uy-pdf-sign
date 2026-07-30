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
