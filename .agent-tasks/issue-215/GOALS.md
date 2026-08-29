# Issue 215 acceptance goals

- Publishing handshake metadata for a lease already registered at the peer address does not cancel that lease.
- Publishing a genuinely different lease at the same address still cancels and replaces the predecessor.
- The production `BlockSync::peer_registration_handle` updates peer metadata for both cases and reports replacement only for a different connection.
- Focused node tests, formatting, and relevant lint checks pass.
