# Upgrading from 1.x to 2.0

Version 2.0 replaces the decoder with a dependency-free implementation that follows the current BOLT #11 specification. The public API changed in the process: decoding now returns an immutable object in one step, instead of an array that a denormalizer turns into a mutable object.

Version 1.x receives security fixes for twelve months after 2.0.0 is released, so there is time to migrate.

## Requirements

| 1.x                                                          | 2.0                                   |
|--------------------------------------------------------------|---------------------------------------|
| PHP 7.4 or later                                             | PHP 8.3 or later, 64-bit              |
| `ext-bcmath`, `ext-gmp`, `ext-mbstring`                      | `ext-gmp`                             |
| `protonlabs/bitcoin` (BitWasp) and its dependencies          | no Composer dependencies              |

Removing BitWasp also takes its elliptic-curve libraries out of your dependency tree, together with the `ext-secp256k1` code path of 1.x, which static analysis showed could not decode any invoice.

## Decoding

Before:

```php
use Jorijn\Bitcoin\Bolt11\Encoder\PaymentRequestDecoder;
use Jorijn\Bitcoin\Bolt11\Normalizer\PaymentRequestDenormalizer;

$decoder = new PaymentRequestDecoder();
$denormalizer = new PaymentRequestDenormalizer();
$paymentRequest = $denormalizer->denormalize($decoder->decode($invoice));
```

After:

```php
use Jorijn\Bitcoin\Bolt11\PaymentRequestDecoder;

$paymentRequest = (new PaymentRequestDecoder())->decode($invoice);
```

* The decoder moved from `Jorijn\Bitcoin\Bolt11\Encoder\PaymentRequestDecoder` to `Jorijn\Bitcoin\Bolt11\PaymentRequestDecoder` and implements `PaymentRequestDecoderInterface`, for type hints and test doubles.
* Its constructor no longer takes a BitWasp `EcAdapterInterface`. It takes one option, `lenient`; see below.
* The `Normalizer` namespace is gone. If you used the array from `decode()` directly, call `toArray()` on the result instead; the keys are listed below.
* `convert()`, `hrpToSat()` and `hrpToMillisat()` on the decoder are gone; they were helpers, not decoding.

## Strict by default

1.x accepted many invoices that the specification tells a reader to reject. 2.0 rejects them, which is what you want before paying. The one you are most likely to meet is an invoice without a payment secret (`s`): the specification made it mandatory after the first invoices were written, so old invoices fail with `payment request has no payment secret (s)`.

To keep reading such invoices, for example to show a payment history, decode them in lenient mode:

```php
$decoder = new PaymentRequestDecoder(lenient: true);
```

The README lists exactly what lenient mode relaxes. It never relaxes the checksum, the signature or the amount.

A few invoices are rejected in both modes where 1.x accepted them:

* An invoice without a payment hash (`p`): there is nothing to pay.
* A tagged field that runs past the end of the invoice.
* An amount with leading zeros (`lnbc01m...`) or of zero.
* An `x` or `c` field too large for a 64-bit integer.

## The payment request object

`Jorijn\Bitcoin\Bolt11\Model\PaymentRequest` is now `final` and `readonly`. It has no setters, and every field has its own getter instead of a tag.

| 1.x                                                       | 2.0                                                     |
|-----------------------------------------------------------|---------------------------------------------------------|
| `findTagByName(Tag::PAYMENT_HASH)->getData()`              | `getPaymentHash()`                                      |
| `findTagByName(Tag::SECRET)->getData()`                    | `getPaymentSecret()`                                    |
| `findTagByName(Tag::DESCRIPTION)->getData()`               | `getDescription()`                                      |
| `findTagByName(Tag::PURPOSE_COMMIT_HASH)->getData()`       | `getDescriptionHash()`, and `verifyDescriptionHash()`   |
| `findTagByName(Tag::PAYEE_NODE_KEY)->getData()`            | `getPayeeNodeKey()` (always set: from `n`, or recovered) |
| `findTagByName(Tag::EXPIRE_TIME)->getData()`               | `getExpiry()` (3600 when the invoice has no `x`)        |
| `findTagByName(Tag::MIN_FINAL_CLTV_EXPIRY)->getData()`     | `getMinFinalCltvExpiryDelta()` (18 when it has no `c`)  |
| `findTagsByName(Tag::FALLBACK_ADDRESS)`                    | `getFallbackAddresses()`                                |
| `findTagsByName(Tag::ROUTING_INFO)`                        | `getRouteHints()`                                       |
| `getTags()` with `UnknownTag` entries                      | `getUnknownFields()`                                    |
| `getTimestamp()` (int)                                     | `getTimestamp()` (`DateTimeImmutable`, UTC); use `->getTimestamp()` on it for the int |
| `getTimestampDateTime()`                                   | `getTimestamp()`                                        |
| `getExpiryTimestamp()`                                     | `getExpiresAt()->getTimestamp()`                        |
| `getExpiryDateTime()`                                      | `getExpiresAt()`                                        |
| `getNetwork()` (a BitWasp `NetworkInterface`)              | `getNetwork()` (the `Network` enum)                     |
| `getSatoshis()`, `getMilliSatoshis()`                      | unchanged; `getSatoshis()` still rounds down            |
| `getPrefix()`, `getSignature()`, `getRecoveryFlag()`       | unchanged                                               |

New in 2.0: `getFeatures()` (field `9`), `getMetadata()` (field `m`), `isExpired()`, and taproot and other segwit v1+ fallback addresses (1.x skipped them).

The classes `Tag`, `TagInterface` and `UnknownTag` are gone.

### Networks

`getNetwork()` returns `Jorijn\Bitcoin\Bolt11\Model\Network` instead of a BitWasp network object:

| 1.x                                                  | 2.0                 |
|------------------------------------------------------|---------------------|
| `BitWasp\Bitcoin\Network\Networks\Bitcoin`           | `Network::Mainnet`  |
| `BitWasp\Bitcoin\Network\Networks\BitcoinTestnet`    | `Network::Testnet`  |
| `Jorijn\Bitcoin\Bolt11\Network\BitcoinSignet`        | `Network::Signet`   |
| `Jorijn\Bitcoin\Bolt11\Network\BitcoinRegtest`       | `Network::Regtest`  |

So `$paymentRequest->getNetwork() instanceof Bitcoin` becomes `$paymentRequest->getNetwork() === Network::Mainnet`. The `Jorijn\Bitcoin\Bolt11\Network` namespace is gone.

### Fallback addresses

`Model\FallbackAddress` is now read-only:

| 1.x                 | 2.0                                                   |
|---------------------|-------------------------------------------------------|
| `getCode()`         | `getVersion()` (`VERSION_P2PKH` = 17, `VERSION_P2SH` = 18, or a witness version) |
| `getAddressHash()`  | `getProgram()`                                        |
| `getAddress()`      | `getAddress()`                                        |

### Route hints

1.x returned one tag per `r` field, holding a list of `RoutingInfo` hops. 2.0 returns a list of `RouteHint` objects, one per `r` field, each with `getHops()`:

| 1.x (`RoutingInfo`)                 | 2.0 (`RouteHintHop`)                                    |
|-------------------------------------|---------------------------------------------------------|
| `getPubKey()`                       | `getPublicKey()`                                        |
| `getShortChannelId()` (hex)         | `getShortChannelId()` (hex), or `getShortChannelIdNotation()` for `589390x3312x1` |
| `getFeeBaseMsat()`                  | unchanged                                               |
| `getFeeProportionalMillionths()`    | unchanged                                               |
| `getCltvExpiryDelta()`              | unchanged                                               |

```php
// 1.x
foreach ($paymentRequest->findTagsByName(Tag::ROUTING_INFO) as $tag) {
    foreach ($tag->getData() as $hop) { /* RoutingInfo */ }
}

// 2.0
foreach ($paymentRequest->getRouteHints() as $routeHint) {
    foreach ($routeHint->getHops() as $hop) { /* RouteHintHop */ }
}
```

### Arrays and JSON

`toArray()` and `json_encode()` give every field with snake_case keys: `prefix`, `network` (the enum value, such as `bc`), `milli_satoshis`, `satoshis`, `timestamp` and `expiry_timestamp` (Unix seconds), `expiry`, `payee_node_key`, `signature`, `recovery_flag`, `payment_hash`, `payment_secret`, `description`, `description_hash`, `min_final_cltv_expiry_delta`, `metadata`, `features`, `fallback_addresses`, `route_hints` and `unknown_fields`. Unlike the array from 1.x, there is no `tags` list, and route hint hops use `public_key` instead of `pubkey`.

## Exceptions

`catch (PaymentRequestDecodeException $e)` keeps working: every exception the decoder throws still extends it. The new `Jorijn\Bitcoin\Bolt11\Exception\ExceptionInterface` is the recommended type to catch.

* `UnableToDenormalizeException` and `UnknownFallbackAddressVersionException` are gone, along with the code that threw them. An unknown fallback address version is skipped, as the specification says.
* `UnknownRequiredFeatureException` is new: the invoice requires a feature this library does not know (strict mode only).
* All exception classes are `final`, except the abstract `PaymentRequestDecodeException`.
