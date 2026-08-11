---
title: Core float parity is value parity, not JSON text parity
date: 2026-08-11
category: docs/solutions/logic-errors
module: crates/rpc/src/context.rs (Core-compatible numeric RPC fields)
problem_type: logic_error
component: rpc
severity: medium
applies_when:
  - "A numeric RPC field is compared against Bitcoin Core"
  - "A floating-point RPC value differs in its serialized spelling from Core"
  - "A compatibility fix is tempted to nudge an f64 to match another serializer"
related_components:
  - bitcoin_core_rpc
  - floating_point_serialization
tags:
  - floating-point
  - bitcoin-core
  - rpc-parity
  - serialization
  - difficulty
---

# Core float parity is value parity, not JSON text parity

## Symptom

On a regtest chain, `getblockchaininfo.difficulty` reported `1.0` in
bitcoin-rs while Bitcoin Core 27.0 reported `4.656542373906925e-10`.
The same difficulty helper also affected `getblockheader`, `getblock`,
`getdifficulty`, and `getmininginfo`.

## Cause

The original calculation divided the current target by the network's own
proof-of-work limit. That makes the easiest target on every network report
`1.0`, even though Core defines difficulty as a multiple of the
difficulty-1 target and therefore uses that network-independent reference
independently of the selected network.

There is a second compatibility trap after the value is corrected. Core's
`GetDifficulty` performs this exact sequence:

1. Compute `0x0000ffff / (nBits & 0x00ffffff)` as `f64`.
2. Repeatedly multiply by `256.0` while the nBits exponent is below 29.
3. Repeatedly divide by `256.0` while the exponent is above 29.

The operation order matters for the final IEEE-754 bit. For
`0x207fffff`, both implementations produce the double whose bits correspond
to `4.6565423739069247e-10`.

Core's RPC layer then formats that double with `%.16g` through UniValue, while
the production RPC path here serializes its `sonic_rs::Value` with
`sonic_rs::to_string`. sonic-rs delegates finite f64 formatting to its
shortest-round-trip `zmij` formatter. Consequently, Core prints
`4.656542373906925e-10` and sonic-rs prints `4.6565423739069247e-10`; these
are different strings even though the underlying value is the same.

## Fix

Compute difficulty with the Core mantissa ratio and the repeated `256.0`
scaling loop. Guard a zero mantissa and return `0.0` for that impossible but
representable header value rather than dividing by zero.

For direct algorithm tests, where both results are still pre-serialization
doubles, assert compatibility at the value level with `f64::to_bits()`. Once
either result has crossed the wire, Core's `%.16g` rendering can parse back to
an adjacent double; compare with an appropriate tolerance or normalize the
wire representation instead of requiring exact parsed-bit equality. Do not
add a one-ULP adjustment to make sonic-rs's shortest spelling resemble Core's
`%.16g` output: that changes the API value and makes it differ from Core's
value precisely to match Core's formatting.

## Why This Works

The mantissa/exponent loop reproduces Core's `GetDifficulty` operation order,
so the returned f64 is bit-for-bit equal to Core's result. The JSON spelling
may still differ because the serializers choose different valid
representations of the same IEEE-754 number.

## Prevention

- Compare direct cross-node floating-point algorithm results by exact value or
  `f64::to_bits()` before serialization. For values parsed from RPC text, use
  a documented tolerance or canonicalize the representation before comparing.
- Preserve the reference implementation's floating-point operation order;
  algebraically equivalent target division or `powi` can change the last bit.
- Treat a rendering mismatch as a serializer issue. Never change a numeric
  value merely to make its text match another implementation.
