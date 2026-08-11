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

Header `count` defaults to 5 and is capped at 2000. Active-chain requests walk
forward by height. A side-branch hash returns only its own header because the
available block-tree accessors do not provide child traversal.

The REST gateway does not change the reported `getnetworkinfo` version. When
using the unmodified `bip300301_enforcer`, pass
`--bitcoin-core-skip-version-check`.

bitcoin-rs also does not currently publish Bitcoin Core's `pubsequence` ZMQ
topic. Normal enforcer mempool synchronization therefore requires an explicit
`--node-zmq-addr-sequence` pointing at a compatible external publisher, or a
no-mempool/bounded enforcer mode.

REST is off by default. With REST disabled, `/rest/*` returns HTTP 404.
