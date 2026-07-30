# Using firmauy as a library

FirmaUY is primarily a command-line tool, but its core is also exposed as a small public API,
`firmauy.api`, so you can verify, sign and diagnose from your own Python program without shelling out
to the CLI. Every function returns plain dataclasses, never printed text or process exit codes, so
the results are easy to consume. This is the same API a GUI front-end can build on.

> **Status:** the public API is new as of 1.6.0 and may still evolve. The CLI remains the primary,
> most stable interface. As with the rest of FirmaUY, none of this is officially certified.

## Install

```bash
pip install firmauy      # or: uv add firmauy
```

Then import what you need:

```python
from firmauy.api import verify_file, sign_file, run_doctor
```

## Verify a signature

`verify_file()` verifies a PDF, XAdES XML or detached CMS `.p7s`, auto-detecting the format. It needs
no card or PIN.

```python
from firmauy.api import verify_file

report = verify_file("contract.pdf")
print(report.indication)          # "VALID" / "INDETERMINATE" / "INVALID"
for sig in report.signatures:
    print(sig.signer, sig.trusted)
```

For a detached `.p7s`, pass the original file it signs. The default follows the
`<name>.p7s -> <name>` convention:

```python
report = verify_file("data.bin.p7s", original="data.bin")
```

Returns a `VerifyReport(indication, signatures)`, where each signature is a
`firmauy.verify_common.VerifyResult`.

## Sign a file

`sign_file()` signs a file with the cédula, producing a detached CAdES-BES `.p7s`. The original file
is left untouched. It is the programmatic form of `sign-any`.

```python
import getpass
from firmauy.api import sign_file

report = sign_file("contract.pdf", getpass.getpass("Cédula PIN: "), native=True)
print(report.output_path)         # Path to the produced .p7s
print(report.signer)              # signer common name
```

The `pin` is supplied directly and stays in your process's memory, never in a command line or pipe.
It is verified only after the PIN-free certificate read, so a reader or card problem cannot spend a
card retry. **A wrong PIN still counts toward the card's retry limit and can block the cédula**, so
handle it with care.

- `native=True` (default) signs over PC/SC, the same path as `--native`. `reader` selects a reader.
- `native=False` uses a PKCS#11 module. `pkcs11_lib` is the module path (the bundled middleware by
  default, or e.g. OpenSC's `opensc-pkcs11.so`), `token_label` picks a token and `cert_id` pins the
  signing certificate.
- `output` overrides the default `<input>.p7s` path. `tsa_url` adds an RFC 3161 timestamp.
- `verify=True` re-checks the fresh signature for integrity before returning.

Returns a `SignReport(output_path, signer, issuer)`. Raises on any error, such as an empty PIN, a
missing input, an existing output, or a card or PIN failure.

## Diagnose the environment

`run_doctor()` runs the same checks as the `doctor` command and returns them as data, printing
nothing. It needs no card or PIN.

```python
from firmauy.api import run_doctor

report = run_doctor(native=True)
print(report.ok)                  # False if any check FAILed (a WARN does not fail)
for check in report.checks:
    print(check.status, check.name, check.detail)   # status: PASS / WARN / FAIL
```

`native=True` (default) checks the PC/SC reader and card that native signing uses. Set it False to
check the PKCS#11 middleware module at `pkcs11_lib` instead.

Returns a `DoctorReport(ok, checks)`, where each check is a `DoctorCheck(status, name, detail, fix)`.

## Notes

- These functions never prompt. `sign_file` takes the PIN as an argument, so your program collects
  it. For a terminal prompt, `getpass.getpass` keeps it off the screen.
- They do blocking I/O against the card and filesystem, so run them off the UI thread in a GUI.
- Verifying needs no card, so `verify_file` is safe to call anywhere, including in tests.
