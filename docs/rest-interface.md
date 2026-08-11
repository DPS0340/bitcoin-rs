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

Active-chain requests walk forward by height. A side-branch hash returns only
its own header because the available block-tree accessors do not provide child
traversal. A well-formed but unknown block hash returns HTTP 200 with an empty
JSON array (or an empty hex/binary body), matching Core.

The REST gateway does not change the reported `getnetworkinfo` version. When
using the unmodified `bip300301_enforcer`, pass
`--bitcoin-core-skip-version-check`.

bitcoin-rs also does not currently publish Bitcoin Core's `pubsequence` ZMQ
topic. Normal enforcer mempool synchronization therefore requires an explicit
`--node-zmq-addr-sequence` pointing at a compatible external publisher, or a
no-mempool/bounded enforcer mode.

REST is off by default. With REST disabled, `/rest/*` returns HTTP 404.
Unknown REST routes also return 404; malformed header inputs and unsupported
header extensions return 400. This distinction is load-bearing for the
enforcer: it treats a 404 on `/rest/*` as evidence that REST is not enabled,
so an unknown block hash must not produce a misleading 404.
