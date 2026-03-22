# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

import getpass
import os
import sys
from enum import Enum
from typing import Optional

import typer


class PinSource(str, Enum):
    prompt = "prompt"
    env = "env"
    stdin = "stdin"
    fd = "fd"


def get_pin(source: PinSource, env_var: Optional[str], fd: Optional[int]) -> str:
    if source == PinSource.prompt:
        return getpass.getpass("PIN PKCS#11: ")
    elif source == PinSource.env:
        if not env_var:
            raise typer.BadParameter("--pin-source env requiere --pin-env-var")
        val = os.environ.get(env_var)
        if not val:
            raise RuntimeError(f"Variable de entorno '{env_var}' no definida o vacía.")
        return val
    elif source == PinSource.stdin:
        typer.echo("Leyendo PIN de stdin...", err=True)
        return sys.stdin.readline().rstrip("\n")
    elif source == PinSource.fd:
        if fd is None:
            raise typer.BadParameter("--pin-source fd requiere --pin-fd")
        with os.fdopen(fd, closefd=False) as f:
            return f.readline().rstrip("\n")
    raise AssertionError(f"PinSource no manejado: {source}")
