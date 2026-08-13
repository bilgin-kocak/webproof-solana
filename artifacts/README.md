# Runtime artifacts

Generated TLSNotary presentations can reveal transcript data and are ignored
by git. Only deliberately reviewed, sanitized examples may be committed.

`example/` contains a sanitized run against the official TLSNotary HTTPS
test fixture (`test-server.io`, in-process notary with the upstream example's
dev key, ephemeral verifier key): the request expectations, the notary
verifying key, and the resulting `signed-claim.json`. The binary presentation
itself is not committed.
