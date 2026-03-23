# cedula-uy-pdf-sign

![banner](https://raw.githubusercontent.com/carlosplanchon/cedula-uy-pdf-sign/refs/heads/main/assets/banner.jpg)

Sign PDFs with a Uruguayan national ID (cédula) via PKCS#11, generating an advanced electronic signature compatible with standard PDF signature validators.

[![DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/carlosplanchon/cedula-uy-pdf-sign)


## Legal / Compliance Notice

⚠️ **Important**

This project:

* is **not affiliated with or endorsed by AGESIC**
* does **not claim official certification or compliance**
* is provided **for technical and educational purposes**

While it uses standard cryptographic mechanisms and aims to align with
Uruguayan digital signature practices, **it should not be assumed to be valid
for legal or regulatory use without independent verification**.

Users are solely responsible for ensuring that the generated signatures meet
any legal or regulatory requirements applicable to their use case.

## Scope

This tool focuses on:

* technical integration with PKCS#11
* PDF signing workflows
* reproducibility of signature appearance

It does **not**:

* validate certificates against official trust lists
* provide legal guarantees
* replace certified signing platforms


## Requirements

### Hardware

- Smart card reader compatible with your OS
- Uruguayan ID card (cédula) with active certificate


## Arch Linux (recommended)

This tool is primarily designed for Arch Linux.

### 1. Install smart card stack

```bash
sudo pacman -S pcsclite ccid pcsc-tools opensc
sudo systemctl enable --now pcscd
```

### 2. Install PKCS#11 library (cédula)

Install the PKCS#11 module from AUR:

```bash
yay -S cedula-uruguay-pkcs11
# or manually:
# https://aur.archlinux.org/packages/cedula-uruguay-pkcs11
```

This is a **community-maintained** AUR package that repackages the official cédula drivers distributed by the Uruguayan government. It is not an official government package.

It provides the default PKCS#11 module used by this tool:

```
/usr/lib/pkcs11/libgclib.so
```


## Installation with uv

```bash
uv tool install cedula-uy-pdf-sign
```


## Usage

The CLI tool is invoked as `firmauy`. Use `--help` on any command to see all available options:

```bash
firmauy --help
firmauy sign --help
firmauy sign-batch --help
```

### Sign a single PDF

```bash
firmauy sign input.pdf output_signed.pdf
```

The tool will prompt for the PKCS#11 PIN interactively.

### Custom signature position

```bash
firmauy sign input.pdf output_signed.pdf --x1 20 --y1 20 --x2 225 --y2 90
```

### Specify page (0-indexed, -1 = last page)

```bash
firmauy sign input.pdf output_signed.pdf --page 0
```

### Non-interactive PIN

PIN can be supplied without an interactive prompt via `--pin-source`:

```bash
# From an environment variable
firmauy sign input.pdf output_signed.pdf --pin-source env --pin-env-var MY_PIN

# From stdin
echo "1234" | firmauy sign input.pdf output_signed.pdf --pin-source stdin

# From a file descriptor
firmauy sign input.pdf output_signed.pdf --pin-source fd --pin-fd 3
```

⚠️ Avoid exposing the PIN in shell history or process lists.

### Sign batch

Sign multiple PDFs with a single PKCS#11 session - the card PIN is entered only once.

```bash
# Explicit file list
firmauy sign-batch file1.pdf file2.pdf file3.pdf --output-dir ~/signed

# Whole directory
firmauy sign-batch --input-dir ~/docs --output-dir ~/signed

# Whole directory, recursively
firmauy sign-batch --input-dir ~/docs --recursive --output-dir ~/signed

# Both can be combined
firmauy sign-batch extra.pdf --input-dir ~/docs --output-dir ~/signed
```

Output files are named `<original-name>_firmado.pdf` by default. Change the suffix with `--suffix`:

```bash
firmauy sign-batch --input-dir ~/docs --output-dir ~/signed --suffix _signed
```

The output directory is created automatically if it does not exist.

All options available for `sign` (position, PIN source, reason, TSA, etc.) are also available for `sign-batch`.

⚠️  This tool produces cryptographic signatures. Legal validity depends on applicable regulations and use context.
Make sure you have reviewed all documents before signing them in batch.

### Discover tokens and certificates

List all visible PKCS#11 tokens:

```bash
firmauy list-tokens
```

List certificates available on a token:

```bash
firmauy list-certs
```


## Notes

* The default visual signature appearance was derived by analyzing documents signed with official software.
* This project focuses on practical interoperability rather than strict compliance with any specific implementation.


## Privacy

This tool is designed to run entirely locally.

It does not collect, transmit, or store any user data externally.
All cryptographic operations are performed on the user's machine and/or the connected smart card.

Note: Optional features such as timestamping (TSA) may involve external network requests, depending on user configuration.


## Contributing & reporting issues

Bug reports, questions, and pull requests are welcome. Feel free to open an issue on GitHub.


## Acknowledgements

- [@nicolasgutierrezdev](https://github.com/nicolasgutierrezdev) - @nicolasgutierrezdev - provided reference for signature appearance inspired by signatures generated using the Uruguayan ID (cédula).


## License

This project is licensed under the Apache License 2.0.
