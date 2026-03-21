import pytest
import typer

from cedula_uy_pdf_sign.pin import PinSource, get_pin


class TestGetPinEnv:
    def test_returns_value_from_env(self, monkeypatch):
        monkeypatch.setenv("MI_PIN", "1234")
        assert get_pin(PinSource.env, env_var="MI_PIN", fd=None) == "1234"

    def test_raises_if_env_var_not_set(self, monkeypatch):
        monkeypatch.delenv("PIN_INEXISTENTE", raising=False)
        with pytest.raises(RuntimeError, match="no definida o vacía"):
            get_pin(PinSource.env, env_var="PIN_INEXISTENTE", fd=None)

    def test_raises_if_env_var_name_not_provided(self):
        with pytest.raises(typer.BadParameter):
            get_pin(PinSource.env, env_var=None, fd=None)


class TestGetPinFd:
    def test_raises_if_fd_not_provided(self):
        with pytest.raises(typer.BadParameter):
            get_pin(PinSource.fd, env_var=None, fd=None)
