# Using firmauy as a library

FirmaUY is primarily a command-line tool, but its core is also exposed as a public API,
`firmauy.api`, so you can sign, verify, read the cédula, introspect and diagnose from your own Python
program without shelling out to the CLI. Every function returns plain dataclasses, never printed text
or process exit codes, so the results are easy to consume. This is the same API a GUI front-end can
build on.

> **Status:** the public API is still young and may evolve. The CLI remains the primary, most stable
> interface. As with the rest of FirmaUY, none of this is officially certified.

## Install

```bash
pip install firmauy      # or: uv add firmauy
```

Then import what you need:

```python
from firmauy.api import sign, verify, fetch_identity, run_doctor
```

## Verify a signature

`verify()` verifies a PDF, XAdES XML or detached CMS `.p7s`, auto-detecting the format. It needs
no card or PIN.

```python
from firmauy.api import verify

report = verify("contract.pdf")
print(report.indication)          # "VALID" / "INDETERMINATE" / "INVALID"
for sig in report.signatures:
    print(sig.signer, sig.trusted)
```

For a detached `.p7s`, pass the original file it signs. The default follows the
`<name>.p7s -> <name>` convention:

```python
report = verify("data.bin.p7s", original="data.bin")
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

## Sign a PDF

`sign_pdf()` signs a PDF and returns a PAdES-signed PDF, with the signature embedded rather than
written to a separate `.p7s`. A visible appearance (signer, certificate serial and timestamp) is
stamped on the last page. For a PDF this is usually what you want instead of `sign_file`.

```python
import getpass
from firmauy.api import sign_pdf

report = sign_pdf("contract.pdf", getpass.getpass("Cédula PIN: "), native=True)
print(report.output_path)         # <name>_firmado.pdf by default
```

It takes the same PIN and backend options as `sign_file` (`native`/`reader` or
`pkcs11_lib`/`token_label`/`cert_id`). `reason` and `location` fill the PAdES signature metadata,
`tsa_url` adds an RFC 3161 timestamp, and `verify=True` re-checks the fresh signature for integrity
and whole-file coverage. Returns a `SignReport`.

## Sign an XML

`sign_xml()` signs an XML and returns it with a XAdES-BES signature embedded (XAdES-T with
`tsa_url`). The output defaults to `<name>_firmado.xml`.

```python
from firmauy.api import sign_xml

report = sign_xml("factura.xml", pin, native=True)
print(report.output_path)
```

Same PIN and backend options as `sign_file`. Returns a `SignReport`.

## Sign any file (auto-detect)

`sign()` picks the signature type from the file content: a PDF is signed as PAdES, an XML as XAdES,
and anything else as a detached CAdES `.p7s`. This is the natural single entry point for a GUI
"Sign" button.

```python
from firmauy.api import sign

report = sign("document.pdf", pin, native=True)   # -> PAdES, document_firmado.pdf
```

Pass `sign_as="pdf"`, `"xml"` or `"cades"` to force a type instead of auto-detecting. `reason` and
`location` apply only when the resolved type is a PDF. Returns a `SignReport`.

## Sign several files in one session

`sign_files()` signs a list of files through a single card session, so the PIN is checked once for
the whole batch instead of once per file.

```python
from firmauy.api import sign_files

reports = sign_files(["a.pdf", "b.xml", "c.bin"], pin, native=True)
for r in reports:
    print(r.output_path)
```

Each file's type is resolved like `sign()`. `output_dir` writes the results there instead of next to
each input. Fail-fast: it raises on the first file that fails. Returns a list of `SignReport`.

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

## Read the cédula

`fetch_identity()` and `fetch_photo()` read the card over PC/SC. They need no PIN (the data is public)
and no signing session.

```python
from firmauy.api import fetch_identity, fetch_photo

person = fetch_identity()
print(person.given_names, person.lastnames, person.id_number)

photo = fetch_photo()
open("foto.jpg", "wb").write(photo.data)   # photo.data is the raw JPEG
```

`fetch_identity()` returns an `IdentityReport` (fields the card omits are `None`); `fetch_photo()`
returns a `PhotoReport` with the JPEG in `data`. Do not call these while a PKCS#11 signing session is
open on the same card.

## List readers, tokens and certificates

Introspection helpers, none of which need a PIN (unless a token hides its certificates behind a
login):

```python
from firmauy.api import list_readers, list_tokens, list_certs

list_readers()                       # ["ACS ACR 38U-CCID 00 00", ...]
list_tokens()                        # [TokenInfo(label=..., serial=...), ...]
list_certs(token_label="...")        # [CertInfo(id=..., subject={...}, ...), ...]
```

`list_readers()` returns the reader names (exactly what the `reader=` argument accepts).
`list_tokens()` and `list_certs()` take a `pkcs11_lib` (the bundled middleware by default);
`list_certs()` also accepts `token_label`, `cert_id`, an optional `pin` and `include_pem=True`.

## Validate a cédula number

`validate_ci()` checks a cédula number's check digit (a purely arithmetic consistency check, not an
identity or document check). `complete_ci()` appends the check digit to a body. Both need no card.

```python
from firmauy.api import validate_ci, complete_ci

validate_ci("1.234.567-8").valid    # True / False
complete_ci("1234567")              # body + its check digit
```

## Refresh the national CA certificates

`fetch_cas()` refreshes the national CAs (root + intermediate) into a per-user cache. Verification
already works offline with the bundled anchors, so this is optional.

```python
from firmauy.api import fetch_cas

bundle = fetch_cas()
print(bundle.root_path, bundle.intermediate_path)
```

## Errors

The domain conditions raise typed exceptions (importable from `firmauy.api` or `firmauy.errors`),
so a GUI or script can branch on what happened instead of matching message text:

```python
from firmauy.api import sign, IncorrectPinError, PinLockedError, CardNotFoundError

try:
    report = sign("contract.pdf", pin_provider=ask_pin)
except IncorrectPinError as exc:
    retry(attempts=exc.attempts_remaining)   # None when the backend cannot know (PKCS#11)
except PinLockedError:
    show_unblock_help()
except CardNotFoundError:
    ask_to_insert_card()
```

The hierarchy, under a common `FirmauyError` base:

- `ReaderNotFoundError`, `CardNotFoundError` — no reader / reader present but no card.
- `PinError` — base for PIN problems, with `IncorrectPinError` (carries `attempts_remaining` on the
  native path) and `PinLockedError`.
- `CertificateError` — base, with `CertificateNotFoundError`, `CertificateNotValidError` (expired
  or not yet valid) and `SigningKeyNotFoundError`; plus `TokenNotFoundError` for the PKCS#11 module.
- `OutputExistsError` — the output file exists and `overwrite` was not passed (carries `path`).

Every class also inherits the built-in the engine historically raised (`RuntimeError`, or
`ValueError` where noted), so a broad `except RuntimeError` keeps working. Environment problems
(pcscd down, PKCS#11 module missing) stay plain `RuntimeError` with actionable messages; use
`run_doctor()` to diagnose those in a structured way.

## Notes

- The signing functions take the PIN as `pin` (a string) or as `pin_provider` (a zero-arg callable
  invoked only when the PIN is actually needed, i.e. after the card is confirmed present, so a GUI
  can prompt on demand). Exactly one of the two. For a terminal prompt, `getpass.getpass` keeps it
  off the screen.
- Every result is a dataclass: `VerifyReport`, `SignReport`, `DoctorReport`/`DoctorCheck`,
  `IdentityReport`, `PhotoReport`, `TokenInfo`, `CertInfo`, `CiReport`, `CaBundle`.
- They do blocking I/O against the card and filesystem, so run them off the UI thread in a GUI.
- Verifying and the pure utilities (`validate_ci`, `complete_ci`) need no card, so they are safe to
  call anywhere, including in tests.
