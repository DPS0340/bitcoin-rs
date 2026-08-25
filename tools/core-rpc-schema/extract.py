#!/usr/bin/env python3
"""Extract Bitcoin Core's declared RPC result schemas from its own source.

#78 asks for the supported surface to be verified against a pinned Core
reference, and the obvious way to do that is to run one and compare answers.
That needs a `bitcoind` binary matching the pin -- and the pin is 31.99.0, a
master snapshot, for which no release binary exists. Waiting for a release
before checking anything is a long time to check nothing.

Core declares each method's result shape in the source, next to the handler, as
`RPCResult` literals. Those declarations are what `bitcoin-cli help` prints and
what Core's own `RPCHelpMan::Check` asserts its handlers against in debug
builds, so they are not documentation that drifts -- they are checked against
Core's behaviour by Core.

This reads them out. The result is a machine-readable schema per method: the
result type, and for object results the field names, their types, and whether
each is optional. That is enough to answer "does this node emit the fields Core
emits, with the types Core gives them" without running anything.

What it does not answer is values. That still needs a live Core, and #78 keeps
those two apart on purpose: the portable check runs in CI, the live one is
documented and reproducible.

Usage:

    python3 tools/core-rpc-schema/extract.py \\
        --core ~/.cargo/registry/src/*/libbitcoinkernel-sys-0.3.0/bitcoin \\
        --out docs/api/core-rpc-schema.json

The output carries provenance -- the Core version it came from and the files it
read -- because a schema with no source is a claim with no evidence.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# `RPCMethod <name>()` / `RPCHelpMan <name>()` open a method definition. Core
# uses both spellings across the tree, and not every one is `static` --
# `getblockchaininfo` is not, and requiring it silently dropped eleven methods.
METHOD_RE = re.compile(r"^(?:static\s+)?(?:RPCMethod|RPCHelpMan)\s+(\w+)\(\)", re.M)

# One declared field: `{RPCResult::Type::NUM, "blocks", "the height"}`, with an
# optional `/*optional=*/true` between the name and the description. The
# description is skipped -- it is prose, and prose is not a contract.
FIELD_RE = re.compile(
    r"\{\s*RPCResult::Type::(\w+)\s*,\s*"
    r'"((?:[^"\\]|\\.)*)"\s*,\s*'
    r"(?:/\*\s*optional\s*=\s*\*/\s*(true|false)\s*,\s*)?"
)

# A field Core appends conditionally:
#
#     list.emplace_back(RPCResult::Type::BOOL, "fullrbf", "... (DEPRECATED)");
#
# Same declaration, different syntax, and it has no leading brace so FIELD_RE
# does not see it. Missing them reports the field as one this node invented,
# which is the opposite of the truth. They are recorded optional, because the
# branch that adds them is exactly what makes them conditional.
EMPLACE_RE = re.compile(
    r"emplace_back\(\s*RPCResult::Type::(\w+)\s*,\s*"
    r'"((?:[^"\\]|\\.)*)"'
)

# The `RPCResult{` that opens a result declaration. A method may have several:
# Core lists one per shape the method can return, each labelled with the
# condition it applies under -- `getblock` has one per verbosity, `gettxout` one
# for found and one for not-found. Taking only the first describes the method
# wrongly: `getblock`'s first is the verbosity-0 hex string, while every caller
# that asks for an object is on a later one.
RESULT_OPEN_RE = re.compile(r"RPCResult\{")

# `RPCExamples{` closes the result section. Everything after it is examples and
# then the handler lambda, and the lambda contains braces of its own.
EXAMPLES_RE = re.compile(r"RPCExamples\{")

# The head of one variant: an optional condition string, then the result type
# and its (usually empty) name.
HEAD_RE = re.compile(
    r'\A\s*(?:"((?:[^"\\]|\\.)*)"\s*,\s*)?'
    r"RPCResult::Type::(\w+)\s*,\s*"
    r'"((?:[^"\\]|\\.)*)"'
)

# Core spells "this method returns nothing" a few ways.
NONE_TYPES = {"NONE"}


def method_blocks(source: str) -> list[tuple[str, str]]:
    """Split a translation unit into (method name, body) pairs.

    A body runs to the start of the next method definition, which is coarse but
    sufficient: the result declaration always precedes the handler lambda, and
    the handler cannot contain another `static RPCMethod` at column zero.
    """
    starts = [(m.group(1), m.start()) for m in METHOD_RE.finditer(source)]
    blocks = []
    for index, (name, start) in enumerate(starts):
        end = starts[index + 1][1] if index + 1 < len(starts) else len(source)
        blocks.append((name, source[start:end]))
    return blocks


def balanced(text: str, start: int) -> int:
    """Index one past the brace group opening at `start`."""
    depth = 0
    for index in range(start, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index + 1
    return len(text)


def result_regions(body: str) -> list[str]:
    """Every `RPCResult{...}` in the method's result section, in order.

    Brace-balanced rather than regex-terminated, because a region contains
    nested braces: object field lists, and in a few methods a lambda that builds
    the list conditionally.

    Bounded at `RPCExamples{` so the handler lambda is never walked -- it is
    ordinary C++ and would swallow the scan.
    """
    examples = EXAMPLES_RE.search(body)
    section = body[: examples.start()] if examples else body

    regions = []
    cursor = 0
    while True:
        opened = RESULT_OPEN_RE.search(section, cursor)
        if not opened:
            return regions
        start = opened.end() - 1
        end = balanced(section, start)
        regions.append(section[start:end])
        cursor = end


def parse_variant(region: str) -> dict | None:
    """Turn one `RPCResult{...}` region into a schema for that variant."""
    inner = region[1:-1] if region.startswith("{") else region
    head = HEAD_RE.match(inner)
    if not head:
        return None
    condition, kind = head.group(1), head.group(2)

    schema: dict = {"type": kind}
    if condition:
        schema["when"] = condition
    if kind in NONE_TYPES:
        return schema

    # Fields are the entries after the head. Nested objects and arrays are
    # deliberately flattened away: this extractor claims the *top level* only,
    # and a nested claim it cannot verify is worse than an absent one.
    #
    # "Top level" is found rather than assumed, because Core writes the field
    # list two ways. Usually it is a brace group straight after the head; for a
    # few methods it is built by an immediately-invoked lambda, which nests it
    # deeper. Either way the object's own fields are the shallowest ones
    # present, and anything nested inside them is strictly deeper -- so the
    # minimum observed depth is the top level, whichever form was used.
    seen_at_depth = []
    rest = inner[head.end() :]
    depth = 0
    for match in re.finditer(FIELD_RE.pattern + r"|[{}]", rest):
        token = match.group(0)
        if token == "}":
            depth -= 1
            continue
        if token == "{":
            depth += 1
            continue
        if match.group(2) is not None:
            seen_at_depth.append(
                (
                    depth,
                    {
                        "type": match.group(1),
                        "name": match.group(2),
                        "optional": match.group(3) == "true",
                    },
                )
            )
        # A field match consumes its own opening brace.
        depth += 1

    fields = []
    if seen_at_depth:
        top = min(depth for depth, _ in seen_at_depth)
        fields = [field for depth, field in seen_at_depth if depth == top]

    fields.extend(
        {"type": match.group(1), "name": match.group(2), "optional": True}
        for match in EMPLACE_RE.finditer(rest)
    )

    if fields:
        seen: dict[str, dict] = {}
        for field in fields:
            seen.setdefault(field["name"], field)
        schema["fields"] = list(seen.values())
    return schema


def parse_result(regions: list[str]) -> dict | None:
    """Every shape a method can return, in the order Core declares them."""
    variants = [v for v in (parse_variant(region) for region in regions) if v]
    if not variants:
        return None
    if len(variants) == 1:
        return variants[0]
    return {"variants": variants}


def core_version(core: Path) -> str:
    """The CLIENT_VERSION the tree declares, so the schema names its source."""
    cmake = (core / "CMakeLists.txt").read_text(encoding="utf-8", errors="replace")
    parts = []
    for key in ("MAJOR", "MINOR", "BUILD"):
        found = re.search(rf"set\(CLIENT_VERSION_{key}\s+(\d+)\)", cmake)
        parts.append(found.group(1) if found else "?")
    return ".".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", required=True, type=Path, help="vendored Core tree")
    parser.add_argument("--out", required=True, type=Path, help="schema JSON to write")
    args = parser.parse_args()

    rpc_dir = args.core / "src" / "rpc"
    if not rpc_dir.is_dir():
        print(f"no RPC sources under {rpc_dir}", file=sys.stderr)
        return 1

    methods: dict[str, dict] = {}
    sources = []
    for path in sorted(rpc_dir.glob("*.cpp")):
        source = path.read_text(encoding="utf-8", errors="replace")
        found = 0
        for name, body in method_blocks(source):
            regions = result_regions(body)
            if not regions:
                continue
            schema = parse_result(regions)
            if schema is None:
                continue
            # A name collision across files would silently drop one; Core has
            # none, and saying so out loud is cheaper than finding out later.
            if name in methods:
                print(f"duplicate method {name} in {path.name}", file=sys.stderr)
                return 1
            methods[name] = schema
            found += 1
        if found:
            sources.append({"file": f"src/rpc/{path.name}", "methods": found})

    document = {
        "provenance": {
            "core_version": core_version(args.core),
            "extracted_from": "RPCResult declarations in the Core source tree",
            "sources": sources,
            "note": (
                "Top-level result shape only: nested object and array fields are "
                "not claimed, because this extractor cannot verify them. "
                "Regenerate with tools/core-rpc-schema/extract.py."
            ),
        },
        "methods": dict(sorted(methods.items())),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(document, indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )
    print(f"{len(methods)} methods -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
