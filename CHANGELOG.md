# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0](https://github.com/jorijn/bitcoin-bolt11/compare/v2.0.0...v2.1.0) (2026-11-25)


### Features

* decode and verify BOLT 12 offers, invoice requests and invoices ([#21](https://github.com/jorijn/bitcoin-bolt11/issues/21)) ([938b75e](https://github.com/jorijn/bitcoin-bolt11/commit/938b75ead96440d1a1a8ebdfe8a585f2e0fdded9))

## [2.0.0](https://github.com/jorijn/bitcoin-bolt11/compare/v1.1.0...v2.0.0) (2026-11-25)


### ⚠ BREAKING CHANGES

* Invoices without a payment secret (`s` field) are now rejected. Decoding is strict by default and follows the current BOLT #11 specification exactly, so every invoice the specification tells a reader to reject now fails where 1.x accepted it, such as one with a missing or repeated description, a field of the wrong length or an unknown required feature bit. To read older invoices, for example for a payment history, use `new PaymentRequestDecoder(lenient: true)`, and decode in strict mode before paying. Further breaking changes: requires 64-bit PHP 8.3 or later with ext-gmp and has no other dependencies; `PaymentRequestDecoder::decode()` returns an immutable `PaymentRequest` in one step; the Encoder, Normalizer and Network namespaces, the Tag classes and the BitWasp types are gone. See UPGRADE-2.0.md for the full mapping.

### Features

* v2.0 with a dependency-free core on PHP 8.3 ([ce2f04f](https://github.com/jorijn/bitcoin-bolt11/commit/ce2f04f4c5c888da434e6c02227c6114a15307e5))

## [v1.1.0] - 2026-11-25
A maintenance release without breaking changes: existing code keeps working as it is.

### Added
* Signet (`lntbs`) and regtest (`lnbcrt`) invoices (#9). `getNetwork()` returns the new
  `Jorijn\Bitcoin\Bolt11\Network\BitcoinSignet` or `Jorijn\Bitcoin\Bolt11\Network\BitcoinRegtest`.
  The regtest network extends the one from `bitwasp/bitcoin`, but uses the `bcrt` prefix for
  fallback addresses, as Bitcoin Core does.
* `PaymentRequest::findTagsByName()` returns every tag with a name. Routing hints (`r`) and fallback
  addresses (`f`) may appear more than once, and `findTagByName()` only returns the first.
* The test suite now runs the official BOLT #11 test vectors, and CI tests PHP 7.4 to 8.6 with both
  the lowest and the highest allowed dependencies, plus PHPStan and php-cs-fixer.

### Fixed
* Invoices without an expiry (`x`) field now get the default expiry of 3600 seconds from the
  specification, instead of no expiry at all (#12). Thanks @dsbaars.
* Amounts no longer depend on the global `bcscale()`. When an application had set a scale above 0,
  every invoice with a `p` amount was rejected and whole-satoshi amounts lost their `satoshis` value.
* Every malformed invoice now throws a `PaymentRequestDecodeException`, so one `catch` is enough for
  untrusted input. Before, some escaped as a `TypeError`, `ValueError`, `\Exception` or
  `\RuntimeException`: an oversized `x` or `c` field, a routing (`r`) field with a partial hop, an
  empty or malformed fallback address (`f`), or an invoice too short to hold a signature. An invoice
  that expires after the year 9999 is also rejected now; it could not be denormalized before.
* No more deprecation notices on PHP 8.4 and later (implicitly nullable parameters).
* The README said `getSatoshis()` returns `null` for a fractional number of satoshis. It truncates
  to whole satoshis, and always has; the README now says so.

### Changed
* Requires `ext-mbstring`, which the library already used to decode descriptions.
* Requires `protonlabs/bitcoin` 1.0.10 or later. Older versions resolve to dependencies that crash
  on PHP 8 (`buffertools` 0.5.0) or have a known vulnerability (CVE-2024-33851 in `mdanter/ecc`).
* `composer.lock` is no longer committed. Composer ignores a library's lock file for its users,
  so it only hid what they actually install.

## [v1.0.1] - 2024-07-16

### Added
* Added PHP 8.2 & 8.3 to the test matrix.
* Bumped `protonlabs/bitcoin` to stable. Thanks @fr0N73ND3r.

## [v1.0.0] - 2022-08-20
The project has been around for nearly two years now, so I'm bumping the version to v1.0.0. 

### Fixed
* There was a bug reported where in some cases the `payee_node_key` wasn't calculated correctly.

### Removed
* The minimum supported PHP version is now PHP 7.4.0.

### Added
* The CI process now tests compatibility with PHP 8.1.0 as well.

## [v0.2.0] - 2021-12-07
### Added
* Added support for PHP 8.0.0.

## [v0.1.0] - 2021-01-26
First version

[v1.1.0]: https://github.com/Jorijn/bitcoin-bolt11/compare/v1.0.1...v1.1.0
[v1.0.1]: https://github.com/Jorijn/bitcoin-bolt11/compare/v1.0.0...v1.0.1
[v1.0.0]: https://github.com/Jorijn/bitcoin-bolt11/compare/v0.2.0...v1.0.0
[v0.2.0]: https://github.com/Jorijn/bitcoin-bolt11/compare/v0.1.0...v0.2.0
