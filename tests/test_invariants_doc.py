# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""docs/security-invariants.md makes claims about this repository, and this file holds them up.

The page names tests, cites counterexamples, maps matrix rows to clause labels it quotes, and
links files and anchors. Every one of those is a reference that rots silently: rename a test and
the page cites a ghost, and nothing notices, because documentation has no compiler. The page's
other end, the quotations from Agesic's artifacts and from the law, can only be checked over the
network and with a person deciding what a mismatch means, so that half deliberately lives outside
CI, in scripts/check_mcu_quotes.py. This half is hermetic and runs with every pull request.
"""

from __future__ import annotations

import re
from pathlib import Path

DOCS = Path(__file__).resolve().parent.parent / "docs"
TESTS = Path(__file__).resolve().parent
DOC = (DOCS / "security-invariants.md").read_text()

# The page's own rule, quoted: "Unless a file is named, tests live in
# tests/test_timestamp_status.py". If the page changes that sentence, change this with it.
DEFAULT_TEST_FILE = "test_timestamp_status.py"


def test_every_test_the_page_names_exists_where_the_page_says_it_lives():
    """A cited test that moved or died leaves the page pointing readers at nothing. The page
    promises `pytest -k` finds every name it prints, and that promise is this assert."""
    qualified = re.findall(r"`(test_[a-z0-9_]+\.py)::(test_[a-z0-9_]+)`", DOC)
    assert qualified, "the page names no qualified tests at all, which cannot be right"
    for fname, test in qualified:
        path = TESTS / fname
        assert path.is_file(), f"the page cites {fname} and there is no such file"
        assert f"def {test}(" in path.read_text(), (
            f"the page cites {fname}::{test} and {fname} does not define it")

    named = {test for _, test in qualified}
    bare = set(re.findall(r"`(test_[a-z0-9_]+)`", DOC)) - named
    assert bare, "the page names no bare tests at all, which cannot be right"
    body = (TESTS / DEFAULT_TEST_FILE).read_text()
    for test in sorted(bare):
        assert f"def {test}(" in body, (
            f"the page cites {test} with no file, its rule says that means {DEFAULT_TEST_FILE}, "
            "and it is not there: name the file on the page or move the test")


def test_every_internal_anchor_resolves_to_a_heading():
    """A `#fragment` link is checked by no renderer: GitHub happily renders a link to a heading
    that stopped existing, and the reader lands at the top of the page none the wiser."""
    headings = re.findall(r"^#{1,6} (.+)$", DOC, re.M)
    slugs = {re.sub(r"[^a-z0-9 -]", "", h.lower()).replace(" ", "-") for h in headings}
    targets = re.findall(r"\]\(#([^)]+)\)", DOC)
    assert targets, "the page has no internal anchors at all, which cannot be right"
    for target in targets:
        assert target in slugs, f"#{target} points at no heading on the page"


def test_every_relative_link_resolves_to_a_file():
    """The page links its evidence relatively so the links follow whichever ref it is read at.
    That only works while the targets exist."""
    for target in re.findall(r"\]\(([^)#][^)]*)\)", DOC):
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        assert (DOCS / target).resolve().exists(), f"{target} is linked and does not exist"


def test_every_clause_label_used_resolves_to_a_verbatim_entry():
    """The matrix and the prose cite clauses as [CA.4-6]-style labels, and the page says those
    labels refer to the verbatim list. A label with no entry is a citation of nothing."""
    entries = set(re.findall(r"- \*\*\[([^\]]+)\]\*\*", DOC))
    assert entries, "the verbatim list is empty, which cannot be right"
    refs = set(re.findall(r"\[((?:CA\.4|AD\.1|Ley 18\.600)[^\]]*)\]", DOC))
    for ref in sorted(refs):
        assert ref in entries, f"[{ref}] is cited and the verbatim list has no such entry"


def test_every_counterexample_and_gap_the_page_cites_is_defined():
    """C-numbers and gap numbers are the page's internal cross-references. Citing C9 or gap 12
    after a renumbering is exactly the sort of rot nobody rereads a page to find."""
    counterexamples = {int(n) for n in re.findall(r"- \*\*C(\d), ", DOC)}
    assert counterexamples, "no counterexamples are defined, which cannot be right"
    rows = [line for line in DOC.splitlines() if re.match(r"\| \d \| ", line)]
    cited = {int(n) for row in rows for n in re.findall(r"\bC(\d)\b", row)}
    assert cited <= counterexamples, f"the matrix cites C{sorted(cited - counterexamples)}"

    gaps_section = DOC[DOC.index("## Known gaps"):]
    gaps = {int(n) for n in re.findall(r"^(\d+)\. \*\*", gaps_section, re.M)}
    gap_refs = {int(n) for n in re.findall(r"\bgap (\d+)\b", DOC)}
    assert gap_refs <= gaps, f"the page cites gap {sorted(gap_refs - gaps)} and defines no such gap"


def test_the_matrix_is_rectangular():
    """A markdown table with a short row renders, wrongly, with cells silently shifted into the
    wrong columns. Adding the Limits column is exactly how such a row would appear."""
    lines = DOC.splitlines()
    header = next(line for line in lines if line.startswith("| # | Invariant"))
    rows = [line for line in lines if re.match(r"\| \d \| ", line)]
    assert len(rows) == 8, f"the matrix has {len(rows)} rows and the page promises eight"
    for row in rows:
        assert row.count("|") == header.count("|"), f"short or long row: {row[:60]}..."
