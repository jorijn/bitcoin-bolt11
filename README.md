# A PHP library for Lightning payment requests: BOLT #11 invoices and BOLT #12 offers

[![Latest Stable Version](https://img.shields.io/packagist/v/jorijn/bitcoin-bolt11.svg)](https://packagist.org/packages/jorijn/bitcoin-bolt11)
[![Total Downloads](https://img.shields.io/packagist/dt/jorijn/bitcoin-bolt11.svg)](https://packagist.org/packages/jorijn/bitcoin-bolt11)
[![License](https://img.shields.io/github/license/jorijn/bitcoin-bolt11.svg)](https://packagist.org/packages/jorijn/bitcoin-bolt11)
[![CI](https://github.com/Jorijn/bitcoin-bolt11/actions/workflows/test.yml/badge.svg)](https://github.com/Jorijn/bitcoin-bolt11/actions/workflows/test.yml)

Decodes and verifies Lightning payment requests into immutable PHP objects:

* [BOLT #11](https://github.com/lightning/bolts/blob/master/11-payment-encoding.md) invoices (`lnbc1...`): checks the bech32 checksum and the secp256k1 signature.
* [BOLT #12](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md) offers (`lno1...`), invoice requests (`lnr1...`) and invoices (`lni1...`): checks the TLV encoding and the BIP-340 Schnorr signature. See [BOLT #12](#bolt-12-offers-invoice-requests-and-invoices).

Both enforce the rules the specifications set for readers, and pass every [official test vector](tests/Fixtures/README.md).

The library is pure PHP with no Composer dependencies: the bech32, base58 and secp256k1 code it needs is built in, on top of `ext-gmp`. It decodes; it does not create or sign anything.

The package is still called `jorijn/bitcoin-bolt11`, after what it started with; renaming it would make every user change their `composer.json` for no gain. BOLT #11 lives in the `Jorijn\Bitcoin\Bolt11` namespace, BOLT #12 in `Jorijn\Bitcoin\Bolt12`.

Upgrading from 1.x? See [UPGRADE-2.0.md](UPGRADE-2.0.md).

## Installation

```shell
composer require jorijn/bitcoin-bolt11
```

Requires 64-bit PHP 8.3 or later with the `gmp` extension.

## BOLT #11 invoices

```php
use Jorijn\Bitcoin\Bolt11\PaymentRequestDecoder;

$invoice = 'lnbc9678785340p1pwmna7lpp5gc3xfm08u9qy06djf8dfflhugl6p7lgza6dsjxq454gxhj9t7a0sd8dgfkx7cmtwd68yetpd5s9xar0wfjn5gpc8qhrsdfq24f5ggrxdaezqsnvda3kkum5wfjkzmfqf3jkgem9wgsyuctwdus9xgrcyqcjcgpzgfskx6eqf9hzqnteypzxz7fzypfhg6trddjhygrcyqezcgpzfysywmm5ypxxjemgw3hxjmn8yptk7untd9hxwg3q2d6xjcmtv4ezq7pqxgsxzmnyyqcjqmt0wfjjq6t5v4khxsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsxqyjw5qcqp2rzjq0gxwkzc8w6323m55m4jyxcjwmy7stt9hwkwe2qxmy8zpsgg7jcuwz87fcqqeuqqqyqqqqlgqqqqn3qq9q9qrsgqrvgkpnmps664wgkp43l22qsgdw4ve24aca4nymnxddlnp8vh9v2sdxlu5ywdxefsfvm0fq3sesf08uf6q9a2ke0hc9j6z6wlxg5z5kqpu2v9wz';

$paymentRequest = (new PaymentRequestDecoder())->decode($invoice);

$paymentRequest->getNetwork();         // Network::Mainnet
$paymentRequest->getMilliSatoshis();   // 967878534
$paymentRequest->getSatoshis();        // 967878 (rounded down, see below)
$paymentRequest->getDescription();     // 'Blockstream Store: 88.85 USD for Blockstream Ledger Nano S x 1, ...'
$paymentRequest->getTimestamp();       // DateTimeImmutable 2019-10-30T20:51:43+00:00
$paymentRequest->getExpiresAt();       // DateTimeImmutable 2019-11-06T20:51:43+00:00
$paymentRequest->isExpired();          // true
$paymentRequest->getPayeeNodeKey();    // '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad'
$paymentRequest->getPaymentHash();     // '462264ede7e14047e9b249da94fefc47f41f7d02ee9b091815a5506bc8abf75f'
$paymentRequest->getPaymentSecret();   // '1111111111111111111111111111111111111111111111111111111111111111'
$paymentRequest->getFeatures()->getBits(); // [8, 14]

foreach ($paymentRequest->getRouteHints() as $routeHint) {
    foreach ($routeHint->getHops() as $hop) {
        $hop->getPublicKey();                 // '03d06758583bb5154774a6eb221b1276c9e82d65bbaceca806d90e20c108f4b1c7'
        $hop->getShortChannelIdNotation();    // '589390x3312x1'
        $hop->getFeeBaseMsat();               // 1000
        $hop->getFeeProportionalMillionths(); // 2500
        $hop->getCltvExpiryDelta();           // 40
    }
}
```

Hashes, keys and other binary values are returned as lowercase hex. Timestamps are `DateTimeImmutable` in UTC. Fields the invoice leaves out get the defaults from the specification: an expiry of 3600 seconds and a `min_final_cltv_expiry_delta` of 18.

`toArray()` returns every field as a plain array with snake_case keys, and the object implements `JsonSerializable`, so `json_encode($paymentRequest)` works as well. More examples are in the [examples](examples) directory.

### Description hashes

When the invoice carries a hash of the description (`h`) instead of the description itself (`d`), check the description you were given against it:

```php
if (!$paymentRequest->verifyDescriptionHash($description)) {
    // the description does not belong to this invoice
}
```

### Fallback addresses and features

`getFallbackAddresses()` returns the on-chain addresses (`f`) as the wallet would show them: base58 for P2PKH and P2SH, bech32 for segwit version 0 and bech32m for taproot and later versions, with the prefix of the invoice's network.

`getFeatures()` returns the feature bits (`9`). `supports(Features::BASIC_MPP)` is true when the invoice sets either bit of a feature, `requires()` only for the even bit.

## Strict and lenient decoding

By default the decoder is strict: it rejects every invoice that the specification tells a reader to reject. Some of those rules are newer than the invoices they reject. Most notably, the payment secret (`s`) became mandatory years after the first invoices were written, so older invoices without one fail. For those, there is a lenient mode:

```php
$decoder = new PaymentRequestDecoder(lenient: true);
```

| Invoice                                                                                | Strict  | Lenient                                     |
|----------------------------------------------------------------------------------------|---------|---------------------------------------------|
| No payment secret (`s`), or more than one                                              | reject  | accept, first one wins                      |
| More than one payment hash (`p`)                                                       | reject  | accept, first one wins                      |
| No description (`d`) or description hash (`h`), or more than one                       | reject  | accept, the first of each is returned       |
| A `p`, `s`, `h` or `n` field of the wrong length                                       | reject  | skip the field                              |
| A description that is not valid UTF-8 or contains control characters                   | reject  | accept as is                                |
| A payee node key (`n`) that is not a valid public key                                  | reject  | skip it and recover the key from the signature |
| A signature in high-S form while the invoice has an `n` field                          | reject  | accept                                      |
| An `x`, `c` or `9` field with leading zeros                                            | reject  | accept                                      |
| An empty or malformed fallback address (`f`) or route hint (`r`)                        | reject  | skip the field                              |
| An unknown required (even) feature bit, or `basic_mpp` without `payment_secret`        | reject  | accept; check `getFeatures()` yourself      |

Some checks are never relaxed, because they protect the payer or make the invoice meaningless without them: the bech32 checksum, the signature (and that it matches `n`), the amount, the network, a payment hash being present, and fields that run past the end of the invoice.

Use lenient mode to display or archive invoices. Before paying one, decode it in strict mode: an unknown required feature bit means the payee expects something the payer may not support.

### Displaying descriptions

The description is text chosen by whoever created the invoice. Escape it like any other untrusted input before you put it in HTML, a terminal or a log. In lenient mode it can also contain invalid UTF-8 and control characters.

## Handling invalid invoices

Every exception the decoder throws implements `Jorijn\Bitcoin\Bolt11\Exception\ExceptionInterface`, so one `catch` is enough for input from outside:

```php
use Jorijn\Bitcoin\Bolt11\Exception\ExceptionInterface;

try {
    $paymentRequest = $decoder->decode($invoice);
} catch (ExceptionInterface $exception) {
    // not a valid BOLT #11 invoice; $exception->getMessage() says why
}
```

Catch a subclass when you want to tell reasons apart:

| Exception                                       | When                                                              |
|-------------------------------------------------|-------------------------------------------------------------------|
| `UnableToDecodeBech32Exception`                 | not bech32, or the checksum is wrong (usually a typo)             |
| `UnknownNetworkVersionException`                | a currency prefix other than `bc`, `tb`, `tbs` or `bcrt`          |
| `InvalidAmountException`                        | an amount that is malformed, not whole millisatoshis, or more than 21 million bitcoin |
| `SignatureIncorrectOrMissingException`          | no room for a signature, or a high-S signature with an `n` field   |
| `SignatureDoesNotMatchPayeePubkeyDecodeException` | the signature does not match the payee node key (`n`)           |
| `UnrecoverableSignatureException`               | no public key can be recovered from the signature                 |
| `UnknownRequiredFeatureException`               | the invoice requires a feature this library does not know; `getFeatureBits()` lists them |
| `InvalidPaymentRequestException`                | any other rule of the specification                               |

## Networks

| Prefix   | Network | `getNetwork()`      | Segwit fallback prefix |
|----------|---------|---------------------|------------------------|
| `lnbc`   | mainnet | `Network::Mainnet`  | `bc1`                  |
| `lntb`   | testnet | `Network::Testnet`  | `tb1`                  |
| `lntbs`  | signet  | `Network::Signet`   | `tb1`                  |
| `lnbcrt` | regtest | `Network::Regtest`  | `bcrt1`                |

`Network` is a string-backed enum; its value is the currency part of the prefix (`Network::Signet->value` is `'tbs'`).

## Amounts

`getMilliSatoshis()` returns the exact amount; 1000 millisatoshis is 1 satoshi. `getSatoshis()` rounds down to whole satoshis: an invoice for 1500 millisatoshis returns `1`. Both return `null` for an invoice without an amount, where the payer chooses how much to send.

## BOLT #12: offers, invoice requests and invoices

An offer is a reusable payment code, for a web page or a QR code. A payer's wallet asks the issuer for an invoice over the Lightning network (an invoice request) and pays the invoice it gets back. This library decodes all three; fetching an invoice for an offer is out of scope, because that takes onion messages through a Lightning node.

```php
use Jorijn\Bitcoin\Bolt12\Bolt12Decoder;
use Jorijn\Bitcoin\Bolt12\Model\Chain;

$offer = (new Bolt12Decoder())->decodeOffer('lno1qcp4256ypqpzwyq2p32x2um5ypmx2cm5dae8x93pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpj');

$offer->getDescription();    // 'Test vectors'
$offer->getAmount();         // 10000
$offer->getCurrency();       // 'USD': the amount is in cents; null means millisatoshis
$offer->getMilliSatoshis();  // null, as the amount is in another currency
$offer->getIssuerId();       // '02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'
$offer->getChains();         // [Chain::BITCOIN]: an offer without chains is for Bitcoin
$offer->isExpired();         // false
```

`decodeInvoiceRequest()` and `decodeInvoice()` work the same way, and `decode()` takes any of the three and picks the type by its prefix. An invoice request carries all fields of its offer and an invoice all fields of its request, so `$invoice->getInvoiceRequest()` and `$invoice->getOffer()` give those back:

```php
$invoice = (new Bolt12Decoder())->decodeInvoice($lni);

$invoice->getAmount();                       // millisatoshis
$invoice->getPaymentHash();
$invoice->getNodeId();                       // the key that signed it
$invoice->getExpiresAt();                    // created at + relative expiry (default two hours)
$invoice->getPaths()[0]->getFeeBaseMsat();   // each blinded path with its fees and limits
$invoice->getInvoiceRequest()->getPayerNote();
$invoice->getOffer()->getDescription();
```

Every model has `toArray()` and implements `JsonSerializable`. Binary values are lowercase hex, times are `DateTimeImmutable` in UTC. Chain hashes are hex in the byte order BOLT #12 uses; `Chain::toNetwork()` maps the Bitcoin ones to the `Network` enum.

### What the decoder checks, and what it leaves to you

The decoder enforces every rule for readers that can be checked from the string alone: the TLV encoding, which types each message may contain, unknown even types and feature bits, valid UTF-8, valid public keys, how the fields of an offer combine, and the signature of invoice requests (by `invreq_payer_id`) and invoices (by `invoice_node_id`). For an invoice request it also checks the quantity and the chain against the offer it copies, and the amount when the offer's price is in millisatoshis. An invoice for an offer with an issuer id must be signed by that id.

Some rules depend on context it does not have, so they are yours:

* **Expiry.** Expired offers and invoices are decoded, so they can still be shown. Check `isExpired()` before requesting or paying.
* **The chain.** Check that `getChains()` or `getChain()` is a chain you support.
* **Whether an invoice answers your request.** Compare `$invoice->getInvoiceRequest()` with the request you sent: the specification requires every request field to match. For an offer without an issuer id, check that `getNodeId()` is the final blinded node id of the path you sent the request through.
* **Prices in another currency.** An amount in USD cannot be compared to millisatoshis without an exchange rate, so the decoder does not try.

An invoice request without an offer (a refund, say) is published by its sender, and the specification tells that writer not to sign it. The decoder accepts such a request without a signature, and verifies the signature when there is one. A request for an offer must always be signed.

Payer proofs (`lnp1...`) are not supported yet.

### Handling invalid BOLT #12 strings

Every BOLT #12 exception extends `Jorijn\Bitcoin\Bolt12\Exception\Bolt12DecodeException`, which implements the same `ExceptionInterface` as the BOLT #11 exceptions, so one `catch` covers both:

| Exception                         | When                                                                          |
|-----------------------------------|-------------------------------------------------------------------------------|
| `InvalidEncodingException`        | invalid characters, mixed case, a stray `+`, bad padding, or the wrong prefix |
| `MalformedTlvException`           | a broken TLV stream, or a field with the wrong length or layout               |
| `UnknownRequiredFieldException`   | an even TLV type this library does not know; `getType()` says which           |
| `UnknownRequiredFeatureException` | an even feature bit this library does not know; `getFeatureBits()` lists them |
| `InvalidSignatureException`       | a missing signature, or one that does not match the key                       |
| `InvalidFieldException`           | any other rule of the specification                                           |

The description, the issuer and the payer note are text chosen by whoever wrote the message, and nothing vouches for them. An issuer that says "example.com" is not proof that the offer comes from example.com. Escape them like any other untrusted input.

## Security notes

The signature check is what ties an invoice to its payee, so it is never skipped and never relaxed. The secp256k1 code in this library (ECDSA for BOLT #11, BIP-340 Schnorr for BOLT #12) is **not constant-time**. That is fine for what it does: verifying a signature or recovering a public key only touches public data, so there is no secret that timing could leak. Do not use it to sign anything.

Invoices can be long (a few thousand characters with many route hints), but decoding is linear in their length and the decoder rejects fields that do not fit.

## Support

Version 2.x is the maintained version. Version 1.x receives security fixes for twelve months after the release of 2.0.0.

## Contributing and releases

Releases are automated with [release-please](https://github.com/googleapis/release-please). It reads the commit messages on `master`, so they follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/). The type decides whether a commit ends up in a release:

| Commit message                                                     | Effect                                         |
|--------------------------------------------------------------------|------------------------------------------------|
| `fix: reject invoices with an empty f field`                       | patch release (2.0.0 → 2.0.1), under Bug Fixes |
| `feat: decode BOLT 12 offers`                                      | minor release (2.0.0 → 2.1.0), under Features  |
| `feat!: require PHP 8.4`, or a `BREAKING CHANGE:` footer           | major release (2.x → 3.0.0)                    |
| `deps: …`                                                          | patch release, under Dependencies              |
| `docs:`, `test:`, `ci:`, `build:`, `chore:`, `refactor:`, `style:` | no release, not in the changelog               |

With a squash merge, the pull request title becomes the commit message, so the title needs the type (`fix: …`, `feat: …`); the commit messages inside the pull request are then ignored. With a merge commit, release-please reads every commit in the pull request instead.

After each push to `master`, release-please keeps one open pull request up to date with the next version and its CHANGELOG entry. Merging that pull request tags the version, publishes the GitHub release, and Packagist picks up the tag.

To run the checks locally: `vendor/bin/phpunit`, `vendor/bin/phpstan analyse` and `vendor/bin/php-cs-fixer fix --dry-run --diff`.

## Thanks

This library is based on other BOLT #11 libraries from other programming languages. Special thanks to:

* https://github.com/lightningnetwork/lnd/blob/master/zpay32/decode.go
* https://github.com/bitcoinjs/bolt11
* https://github.com/nievk/bolt11

## CLI tool

There is a CLI tool based on this library. It allows for easy decoding and converting of payment requests into JSON, XML, YAML & CSV. Download and usage here: https://github.com/Jorijn/bitcoin-bolt11-cli
