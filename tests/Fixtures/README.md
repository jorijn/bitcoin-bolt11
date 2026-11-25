# Test fixtures

## bolt11-invoice-test.json

The official BOLT #11 test vectors, copied unmodified from
[`bolt11/invoice-test.json`](https://github.com/lightning/bolts/blob/191462825ae341f0a27098765c075f01ca9bc6c2/bolt11/invoice-test.json)
in the [lightning/bolts](https://github.com/lightning/bolts) repository at commit
`191462825ae341f0a27098765c075f01ca9bc6c2` (2026-10-19).

That work is licensed under the
[Creative Commons Attribution 4.0 International License](http://creativecommons.org/licenses/by/4.0/).

To update: copy the file from a newer commit, update the hash above, and run
`vendor/bin/phpunit --group spec-known-failure` to see whether the list of
known failures in `tests/Spec/Bolt11TestVectorsTest.php` needs adjusting.
