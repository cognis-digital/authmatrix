# Demo 01 - Basic authorization-matrix scan

This demo audits a small e-commerce API's access-control matrix
(`matrix.json`). It is a **defensive / authorized-testing** scenario: the
`observations` block is assumed to come from a test harness run against a
system you own or are explicitly authorized to assess. AUTHMATRIX never makes
requests itself — it only analyzes the recorded results.

## The matrix

Four roles (`anon`, `user`, `support`, `admin`) across six endpoints. The
`policy` block is the *intended* access-control rules; the `observations`
block is what each role *actually* received during testing. AUTHMATRIX maps
each observed HTTP status to an effective decision (2xx/3xx = allow,
401/403/404/4xx = deny, 5xx = inconclusive) and compares it against policy.

## Run it

```sh
python -m authmatrix scan demos/01-basic/matrix.json
python -m authmatrix scan demos/01-basic/matrix.json --format json
python -m authmatrix scan demos/01-basic/matrix.json --fail-on high
cat demos/01-basic/matrix.json | python -m authmatrix scan -
```

## What it should find

| Role    | Endpoint       | Issue                                                          | Severity |
|---------|----------------|----------------------------------------------------------------|----------|
| anon    | get_user_pii   | IDOR — unauthenticated caller read sensitive PII (deny->allow) | CRITICAL |
| anon    | admin_console  | admin shell served to anon (deny->allow, 302)                  | CRITICAL |
| user    | refund_order   | privilege escalation — user can refund (deny->allow)           | HIGH     |
| support | admin_export   | undeclared endpoint reachable, no policy rule (MISSING_DENIAL) | MEDIUM   |
| user    | get_own_order  | legit user denied own order (allow->deny, BROKEN_ALLOW)        | MEDIUM   |
| admin   | admin_console  | 5xx during test, inconclusive (SERVER_ERROR)                   | INFO     |

The process exits non-zero because findings exist. A clean matrix exits `0`;
a read/parse error exits `2`. Use `--fail-on high` in CI to gate only on
serious authorization bypasses while still printing lower-severity gaps.
