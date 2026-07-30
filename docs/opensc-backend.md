# Signing with the OpenSC backend

FirmaUY normally signs through the proprietary cédula PKCS#11 middleware (`libgclib.so`, the AUR
`cedula-uruguay-pkcs11` package), or over PC/SC with
[`--native`](usage.md#native-signing-no-pkcs11-middleware). This guide covers a third path: signing
through [OpenSC](https://github.com/OpenSC/OpenSC), the open-source smart-card framework, using its
`opensc-pkcs11.so` module.

[@nicolasgutierrezdev](https://github.com/nicolasgutierrezdev) and I are bringing support for the
Uruguayan cédula to OpenSC, so the card works through a fully open-source PKCS#11 stack instead of
the proprietary middleware. The driver is already merged upstream.

> **Status:** the driver is merged into OpenSC `master` but not yet in a released version, so for
> now you build OpenSC from source. This backend is experimental and, as with the rest of FirmaUY,
> is not officially certified.

## Why

- **Fully open source.** `opensc-pkcs11.so` and its cédula driver are open source, unlike the
  proprietary `libgclib.so`.
- **Standard stack.** OpenSC is the de-facto PKCS#11 framework on Linux, so the same module also
  works with Firefox/NSS and other PKCS#11-aware software.
- **Complements `--native`.** Same card, but the on-card signing protocol lives in a maintained,
  widely used framework instead of FirmaUY's own APDU code.

## Prerequisites (Arch Linux)

Build tools plus the smart-card and crypto libraries:

```bash
sudo pacman -S --needed base-devel git autoconf automake libtool pkgconf pcsclite openssl
sudo systemctl enable --now pcscd
```

The `opensc` package in the repos is the released version, which does **not** yet include the cédula
driver. We build our own below into a private prefix and do not rely on the system one.

## Build OpenSC from source

Everything installs into a local prefix under your home, so nothing touches the system `opensc`:

```bash
git clone https://github.com/OpenSC/OpenSC.git
cd OpenSC
./bootstrap

PREFIX="$HOME/.local/opensc-cedula"
./configure --prefix="$PREFIX" \
    --enable-cvcdir="$PREFIX/etc/eac/cvc" \
    --enable-x509dir="$PREFIX/etc/eac/x509" \
    --enable-p11_system_config_modules="$PREFIX/share/p11-kit/modules"

make -j"$(nproc)"
make install
```

The three `--enable-*dir` flags matter. By default OpenSC installs a couple of data files to
`/etc/eac/cvc` and `/usr/share/p11-kit/modules`, absolute paths that ignore `--prefix` and need
root, so a plain `make install` fails as a normal user. Pointing them inside the prefix lets the
install finish without root. None of those files are needed for contact-interface signing.

The module you want is:

```bash
MOD="$PREFIX/lib/opensc-pkcs11.so"
```

## Point FirmaUY at it

Every command that takes `--pkcs11-lib` accepts this module. With the cédula in the reader, confirm
it is seen first (no PIN needed):

```bash
firmauy list-tokens --pkcs11-lib "$MOD"     # the cédula token
firmauy list-certs  --pkcs11-lib "$MOD"     # your signing certificate
```

Then sign and verify as usual:

```bash
firmauy sign-pdf document.pdf --pkcs11-lib "$MOD"   # prompts for the PIN
firmauy verify-pdf document_firmado.pdf
```

`verify-pdf` needs no card and no module: it checks integrity, coverage and the certificate chain up
to the Uruguayan national root, exactly as with any other backend.

## Notes

- **Do not run this while the Gemalto middleware holds the card.** Both go through `pcscd` and will
  conflict. Close any other PKCS#11 session first. This is the same caveat as `--native`.
- **It does not touch your system `opensc`.** The module's `RUNPATH` points at the prefix, so it
  loads the freshly built `libopensc` (with the driver), not the system one, even though they share
  a soname. No `LD_LIBRARY_PATH` is needed.
- **`MOD` is a shell variable.** It only exists in the shell where you set it. Re-set it, or use the
  full path, in a new terminal.
- **Staying current.** Until a released OpenSC ships the driver, pull and rebuild to pick up fixes:
  `git pull && make -j"$(nproc)" && make install`.

## What the driver does

Under the hood the OpenSC driver (`card-cedulauy.c` and `pkcs15-cedulauy.c`) exposes the card's
RSA-2048 signing key as a PKCS#15 object and performs the signature with the card's IAS-ECC
operations (`MSE:SET DST`, then `PSO:HASH` and `PSO:CDS`). That is the same on-card protocol
documented for `--native` in the [card protocol reference](card-protocol.md), which is why both
backends produce identical signatures.
