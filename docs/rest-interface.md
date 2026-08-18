# REST interface

bitcoin-rs can expose the small Bitcoin Core-compatible REST surface needed by
remote chain validators. REST uses the existing JSON-RPC listener and port; it
does not create a second listener. Enable it with Core-style configuration:

```ini
rest=1
```

The REST requests are unauthenticated, as in Bitcoin Core. JSON-RPC requests on
the same listener continue to require their configured authentication. Select
the listener with the existing `--rpc-bind` option (or its layered config
equivalent).

Currently implemented endpoints are:

* `GET /rest/chaininfo.json`
* `GET /rest/headers/{hash}.json?count=N`
* `GET /rest/headers/{hash}.hex`
* `GET /rest/headers/{hash}.bin`

Header `count` defaults to 5 and must be in the inclusive range 1–2000.
Out-of-range, negative, non-numeric, and overflowing values return HTTP 400
with Core's invalid-count message. Unknown query parameters are ignored, so
cache-buster parameters do not affect the response.

Active-chain requests walk forward by height from the applied tip. A
side-branch, orphaned, or header-only hash above the applied tip returns HTTP
200 with an empty JSON array (or an empty hex/binary body), just like an
unknown well-formed hash, because Core only walks hashes contained in its
active chain. If no applied tip is published, tree-known hashes likewise
return an empty response. Cache-only records that are not yet represented in
the tree use the existing singleton fallback because their active-chain
membership cannot be established from the tree.

The REST gateway does not change the reported `getnetworkinfo` version. When
using the unmodified `bip300301_enforcer`, pass
`--bitcoin-core-skip-version-check`.

bitcoin-rs publishes the Core-compatible `pubsequence` ZMQ topic with block
connect (`C`) and disconnect (`D`) events. The configured endpoint is reported
by `getzmqnotifications`, so the unmodified enforcer can discover it through
its normal startup path rather than requiring an external publisher or an
explicit `--node-zmq-addr-sequence`. Mempool `A`/`R` events remain intentionally
absent until the mempool has per-transaction event sequencing and explicit
removal reasons.

REST is off by default. With REST disabled, `/rest/*` returns HTTP 404.
Unknown REST routes also return 404; malformed header inputs and unsupported
header extensions return 400. A missing header extension returns HTTP 404 with
`output format not found`, while an unsupported extension such as `.txt`
returns HTTP 400 with `Invalid hash: <hash>`. This distinction is load-bearing
for the enforcer: it treats a 404 on `/rest/*` as evidence that REST is not
enabled, so an unknown or non-active block hash must not produce a misleading
404.

The checked-in default Compose stack supplies the REST, `pubsequence`,
version-check bypass, and drynet4 network settings required to run the
unmodified enforcer in block-only mode. It deliberately omits `--enable-mempool`
until `pubsequence` also provides transaction `A`/`R` events.
