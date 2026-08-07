import re
from pathlib import Path

import pytest
from PIL import Image

from firmauy.appearance import (
    ensure_output_parent,
    make_appearance_pdf,
    split_signer_name,
    wrap_line,
)
from firmauy.constants import (ImageMode, STAMP_FONT_NAME, STAMP_FONT_SIZE,
                               STAMP_LEADING, STAMP_TEXT_Y, StampFields)


class TestWrapLine:
    def test_short_text_single_line(self):
        lines = wrap_line("Hola", STAMP_FONT_NAME, STAMP_FONT_SIZE, max_width=200)
        assert lines == ["Hola"]

    def test_long_text_multiple_lines(self):
        text = " ".join(["Palabra"] * 20)
        lines = wrap_line(text, STAMP_FONT_NAME, STAMP_FONT_SIZE, max_width=100)
        assert len(lines) > 1

    def test_single_oversized_word_not_broken(self):
        # Una sola palabra que excede max_width no se rompe
        lines = wrap_line("Superlargapalabra", STAMP_FONT_NAME, STAMP_FONT_SIZE, max_width=1)
        assert lines == ["Superlargapalabra"]

    def test_empty_string_returns_empty(self):
        assert wrap_line("", STAMP_FONT_NAME, STAMP_FONT_SIZE, max_width=200) == []


class TestSplitSignerName:
    def test_short_name_single_line(self):
        lines = split_signer_name("Ana Gomez")
        assert len(lines) == 1
        assert lines[0].startswith("Firmado por: ")
        assert "Ana Gomez" in lines[0]

    def test_long_name_splits_into_two_lines(self):
        # Un nombre suficientemente largo para no entrar en una sola línea
        long_name = "Juan Domingo Perez Hernandez de los Santos Caballero"
        lines = split_signer_name(long_name)
        assert len(lines) >= 2
        assert lines[0].startswith("Firmado por: ")

    def test_prefix_only_on_first_line(self):
        long_name = "Juan Domingo Perez Hernandez de los Santos Caballero"
        lines = split_signer_name(long_name)
        for line in lines[1:]:
            assert not line.startswith("Firmado por:")

    def test_narrower_max_width_wraps_more(self):
        name = "Juan Domingo Perez Hernandez de los Santos"
        assert len(split_signer_name(name, max_width=60)) >= len(split_signer_name(name, max_width=400))


@pytest.fixture
def sample_png(tmp_path):
    p = tmp_path / "sig.png"
    Image.new("RGBA", (120, 48), (10, 30, 200, 160)).save(p)  # semi-transparent
    return p


class TestImageAppearance:
    @pytest.mark.parametrize("mode", [ImageMode.background, ImageMode.side, ImageMode.only])
    def test_each_mode_produces_valid_pdf(self, tmp_path, sample_png, mode):
        out = tmp_path / f"{mode.value}.pdf"
        make_appearance_pdf(
            str(out), signer="CARLOS ANDRÉS PLANCHÓN PRESTES", cert_serial="78191ABC",
            ts="29/06/2026 12:00", issuer="Autoridad Certificadora del Ministerio del Interior",
            image_path=str(sample_png), image_mode=mode,
        )
        assert out.read_bytes()[:4] == b"%PDF"

    def test_embedding_an_image_grows_the_file(self, tmp_path, sample_png):
        base = tmp_path / "base.pdf"
        make_appearance_pdf(str(base), signer="X", cert_serial="1", ts="t", issuer="i")
        withimg = tmp_path / "img.pdf"
        make_appearance_pdf(str(withimg), signer="X", cert_serial="1", ts="t", issuer="i",
                            image_path=str(sample_png), image_mode=ImageMode.background)
        assert withimg.stat().st_size > base.stat().st_size

    def test_invalid_image_raises_clear_error(self, tmp_path):
        bad = tmp_path / "bad.png"
        bad.write_bytes(b"not an image")
        with pytest.raises(RuntimeError, match="could not load image"):
            make_appearance_pdf(str(tmp_path / "x.pdf"), signer="X", cert_serial="1", ts="t",
                                issuer="i", image_path=str(bad), image_mode=ImageMode.only)

    def test_faded_image_is_a_pale_watermark(self, sample_png):
        from PIL import ImageStat

        from firmauy.appearance import _faded_image

        faded = _faded_image(str(sample_png), 0.2)
        mean = sum(ImageStat.Stat(faded).mean) / 3  # overall brightness across R/G/B
        assert mean > 200  # blended ~80% toward white -> a faint watermark (renderer-independent)


class TestEnsureOutputParent:
    def test_creates_missing_directory(self, tmp_path):
        target = tmp_path / "sub" / "dir" / "file.pdf"
        ensure_output_parent(target)
        assert target.parent.exists()

    def test_existing_directory_no_error(self, tmp_path):
        ensure_output_parent(tmp_path / "file.pdf")  # tmp_path ya existe
        assert tmp_path.exists()


class TestMakeAppearancePdf:
    def test_creates_file(self, tmp_path):
        out = str(tmp_path / "appearance.pdf")
        make_appearance_pdf(
            out,
            signer="Juan Test",
            cert_serial="ABCDEF1234",
            ts="20/03/2026 10:00",
            issuer="Ministerio del Interior",
        )
        assert Path(out).exists()
        assert Path(out).stat().st_size > 0

    def test_output_is_pdf(self, tmp_path):
        out = str(tmp_path / "appearance.pdf")
        make_appearance_pdf(
            out,
            signer="Juan Test",
            cert_serial="ABCDEF1234",
            ts="20/03/2026 10:00",
            issuer="Ministerio del Interior",
        )
        with open(out, "rb") as f:
            header = f.read(4)
        assert header == b"%PDF"


class TestStampFields:
    """Which of the five lines the stamp prints, and where the block sits when some are off.

    The bytes are searched directly because make_appearance_pdf sets setPageCompression(0), so
    the text and its positioning operators are literal in the file. That is what makes it possible
    to assert the default did not move by a single point, which is the thing that must not change:
    every stamp firmauy has ever drawn used these coordinates.
    """

    ARGS = dict(signer="PEREZ PEREZ, JUAN", cert_serial="0123ABCD",
                ts="06/08/2026 10:30", issuer="AC RAIZ NACIONAL")

    def _render(self, tmp_path, name, **kw) -> bytes:
        out = str(tmp_path / f"{name}.pdf")
        make_appearance_pdf(out, **self.ARGS, **kw)
        return Path(out).read_bytes()

    def _first_baseline(self, data: bytes) -> float:
        match = re.search(rb"1 0 0 1 [\d.]+ ([\d.]+) Tm", data)
        assert match, "no text was drawn at all"
        return float(match.group(1))

    def test_every_line_is_printed_by_default(self, tmp_path):
        data = self._render(tmp_path, "full")
        for needle in (b"Firma electr", b"Firmado por", b"Documento", b"Fecha:", b"AC RAIZ"):
            assert needle in data, f"{needle!r} is missing from the default stamp"

    @pytest.mark.parametrize("field,gone,kept", [
        ("title", b"Firma electr", b"Firmado por"),
        ("signer", b"Firmado por", b"Documento"),
        ("document", b"Documento", b"Fecha:"),
        ("date", b"Fecha:", b"AC RAIZ"),
        ("issuer", b"AC RAIZ", b"Firmado por"),
    ])
    def test_turning_one_line_off_removes_that_one_and_no_other(self, tmp_path, field, gone, kept):
        data = self._render(tmp_path, field, fields=StampFields(**{field: False}))
        assert gone not in data
        assert kept in data

    def test_turning_everything_off_draws_no_text_at_all(self, tmp_path):
        data = self._render(tmp_path, "none",
                            fields=StampFields(False, False, False, False, False))
        for needle in (b"Firma electr", b"Firmado por", b"Documento", b"Fecha:", b"AC RAIZ"):
            assert needle not in data

    def test_the_default_block_still_starts_exactly_where_it_always_did(self, tmp_path):
        """The regression this whole feature could have caused. Any change here silently moves
        the stamp on every document signed with defaults."""
        assert self._first_baseline(self._render(tmp_path, "default")) == STAMP_TEXT_Y

    def test_a_shorter_block_slides_down_by_half_of_what_was_removed(self, tmp_path):
        """Otherwise a one-line stamp hangs from the top of a 70pt box with all the air below it."""
        one_off = self._render(tmp_path, "one_off", fields=StampFields(date=False))
        assert self._first_baseline(one_off) == STAMP_TEXT_Y - STAMP_LEADING / 2

        only_signer = self._render(tmp_path, "only_signer",
                                   fields=StampFields(True, True, False, False, False))
        assert self._first_baseline(only_signer) == STAMP_TEXT_Y - 3 * STAMP_LEADING / 2

    def test_a_block_longer_than_five_lines_is_never_pushed_up(self, tmp_path):
        """A name or issuer long enough to wrap already produces more than five lines. Moving
        those up to "center" them would push the first line out through the top of the box."""
        out = str(tmp_path / "long.pdf")
        make_appearance_pdf(out, signer=" ".join(["APELLIDO"] * 8), cert_serial="0123ABCD",
                            ts="06/08/2026 10:30", issuer=" ".join(["AUTORIDAD"] * 6))
        assert self._first_baseline(Path(out).read_bytes()) == STAMP_TEXT_Y
