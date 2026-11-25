# Test fixtures

All files here are copied unmodified from their upstream repositories, so a
diff against upstream shows exactly what changed when they are updated.

## BOLT test vectors

From the [lightning/bolts](https://github.com/lightning/bolts) repository at commit
`191462825ae341f0a27098765c075f01ca9bc6c2` (2026-10-19):

| File here | Upstream file |
| --- | --- |
| `bolt11-invoice-test.json` | [`bolt11/invoice-test.json`](https://github.com/lightning/bolts/blob/191462825ae341f0a27098765c075f01ca9bc6c2/bolt11/invoice-test.json) |
| `bolt12-offers-test.json` | [`bolt12/offers-test.json`](https://github.com/lightning/bolts/blob/191462825ae341f0a27098765c075f01ca9bc6c2/bolt12/offers-test.json) |
| `bolt12-format-string-test.json` | [`bolt12/format-string-test.json`](https://github.com/lightning/bolts/blob/191462825ae341f0a27098765c075f01ca9bc6c2/bolt12/format-string-test.json) |
| `bolt12-signature-test.json` | [`bolt12/signature-test.json`](https://github.com/lightning/bolts/blob/191462825ae341f0a27098765c075f01ca9bc6c2/bolt12/signature-test.json) |
| `bolt12-payer-proof-test.json` | [`bolt12/payer-proof-test.json`](https://github.com/lightning/bolts/blob/191462825ae341f0a27098765c075f01ca9bc6c2/bolt12/payer-proof-test.json) |

That work is licensed under the
[Creative Commons Attribution 4.0 International License](http://creativecommons.org/licenses/by/4.0/).

To update: copy the files from a newer commit, update the hash above, and run
`vendor/bin/phpunit --testsuite default --filter Spec`. Every vector is gated:
a new vector the decoder gets wrong fails the build.

- `tests/Bolt11/Spec/Bolt11TestVectorsTest.php` also lists which invalid
  BOLT #11 vectors lenient mode accepts (`VALID_WHEN_LENIENT`).
- `tests/Bolt12/Spec/Bolt12TestVectorsTest.php` runs the offers, format-string
  and signature vectors, and decodes the signed invoices inside the payer
  proof vectors. Payer proofs themselves (`lnp1...`) are not supported yet.

## BIP-340 test vectors

`bip340-test-vectors.csv` is
[`bip-0340/test-vectors.csv`](https://github.com/bitcoin/bips/blob/0d99ffd39fdaf75209c43b1f8ec3fbbc23f10814/bip-0340/test-vectors.csv)
from the [bitcoin/bips](https://github.com/bitcoin/bips) repository at commit
`0d99ffd39fdaf75209c43b1f8ec3fbbc23f10814` (2026-11-23), available under
BSD-2-Clause, MIT or CC0-1.0. `tests/Bolt11/Internal/Secp256k1Test.php` checks
Schnorr verification against all of them, and the BOLT #12 test signer against
the ones with a secret key.
