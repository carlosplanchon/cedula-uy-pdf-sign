# Contributing to FirmaUY

Bug reports, questions, cookbook recipes and pull requests are welcome. This document covers the
mechanics. The project layout, the test suite and how to develop **without a real card** (SoftHSM2,
since a wrong PIN can block a cédula) are in [docs/development.md](docs/development.md), and the
layer boundaries you should not cross are in [ARCHITECTURE.md](ARCHITECTURE.md).

For security problems, do not open an issue: see [SECURITY.md](SECURITY.md).

## Developer Certificate of Origin (required)

FirmaUY signs legally sensitive documents, so the provenance of its own code matters. Every commit
must be signed off under the [Developer Certificate of Origin 1.1](https://developercertificate.org/):

```bash
git commit -s
```

That adds a `Signed-off-by: Your Name <your@email>` trailer, certifying that you wrote the change
or otherwise have the right to submit it under the project's license (Apache-2.0). Use your real
name and a working email. Pull requests with unsigned commits will be asked to add the sign-off:

```bash
git commit --amend --no-edit -s     # fix the last commit
```

## Signing commits with GPG or SSH (encouraged)

Cryptographically signing your commits is welcome on top of the DCO:

```bash
git commit -s -S
```

It is encouraged, not required: the DCO sign-off plus review is the bar for merging. If you
already have a signing key configured with GitHub, please use it.

## Pull requests

- Run the suite and the linter before pushing:

  ```bash
  uv sync
  uv run pytest
  uvx ruff check src/ tests/
  ```

- Tests must never require a real cédula, a PIN or network access. Integration tests use
  disposable SoftHSM2 tokens, unit tests build certificates in memory.
- Never include real personal data: no names, document numbers, MRZ data, photos, certificates or
  unredacted command output, in code, fixtures, or the pull request itself. Use `--redact` when
  sharing output.
- Keep the engine presentation-free (no printing, no prompts, no typer below the adapters). See
  [ARCHITECTURE.md](ARCHITECTURE.md) for the rules and where things belong.
- English for code, comments, commit messages and docs. Spanish is fine everywhere else
  (issues, discussions, recipes can be bilingual).

## Cookbook recipes

One of the most useful contributions needs no PKCS#11 knowledge at all: a real workflow written up
as a recipe in [docs/cookbook.md](docs/cookbook.md), with minimal commands, expected output,
privacy notes and the environment where it was tested.
