# A PHP library for BOLT #11: Invoice Protocol for Lightning Payments

[![Latest Stable Version](https://img.shields.io/packagist/v/jorijn/bitcoin-bolt11.svg)](https://packagist.org/packages/jorijn/bitcoin-bolt11)
[![Total Downloads](https://img.shields.io/packagist/dt/jorijn/bitcoin-bolt11.svg)](https://packagist.org/packages/jorijn/bitcoin-bolt11)
[![License](https://img.shields.io/github/license/jorijn/bitcoin-bolt11.svg)](https://packagist.org/packages/jorijn/bitcoin-bolt11)
[![CI](https://github.com/Jorijn/bitcoin-bolt11/actions/workflows/test.yml/badge.svg)](https://github.com/Jorijn/bitcoin-bolt11/actions/workflows/test.yml)

This library aims to be a tool to decode BOLT #11 Payment Requests into usable PHP objects. Currently, only decoding is supported. 

BOLT #11 is a simple, extendable, QR-code-ready protocol for requesting payments over Lightning.

## Installation

```shell
$ composer require jorijn/bitcoin-bolt11
```

Requires PHP 7.4 or later with the `bcmath`, `gmp` and `mbstring` extensions.

## Usage

```php
$invoice = 'lnbc9678785340p1pwmna7lpp5gc3xfm08u9qy06djf8dfflhugl6p7lgza6dsjxq454gxhj9t7a0sd8dgfkx7cmtwd68yetpd5s9xar0wfjn5gpc8qhrsdfq24f5ggrxdaezqsnvda3kkum5wfjkzmfqf3jkgem9wgsyuctwdus9xgrcyqcjcgpzgfskx6eqf9hzqnteypzxz7fzypfhg6trddjhygrcyqezcgpzfysywmm5ypxxjemgw3hxjmn8yptk7untd9hxwg3q2d6xjcmtv4ezq7pqxgsxzmnyyqcjqmt0wfjjq6t5v4khxxqyjw5qcqp2rzjq0gxwkzc8w6323m55m4jyxcjwmy7stt9hwkwe2qxmy8zpsgg7jcuwz87fcqqeuqqqyqqqqlgqqqqn3qq9qn07ytgrxxzad9hc4xt3mawjjt8znfv8xzscs7007v9gh9j569lencxa8xeujzkxs0uamak9aln6ez02uunw6rd2ht2sqe4hz8thcdagpleym0j';

$decoder = new \Jorijn\Bitcoin\Bolt11\Encoder\PaymentRequestDecoder();
$denormalizer = new \Jorijn\Bitcoin\Bolt11\Normalizer\PaymentRequestDenormalizer();

$paymentRequest = $denormalizer->denormalize($decoder->decode($invoice));

// satoshis: 967878
echo 'satoshis: ' . $paymentRequest->getSatoshis();

// description: Blockstream Store: 88.85 USD for Blockstream Ledger Nano S x 1, "Back In My Day" Sticker x 2, "I Got Lightning Working" Sticker x 2 and 1 more items
echo 'description: ' . $paymentRequest->findTagByName(\Jorijn\Bitcoin\Bolt11\Model\Tag::DESCRIPTION)->getData();

// timestamp: DateTime Object
// (
//     [date] => 2019-10-30 20:51:43.000000
//     [timezone_type] => 1
//     [timezone] => +00:00
// )
echo 'timestamp: ' . print_r($paymentRequest->getTimestampDateTime(), true);

// hop: 0
// public key: 029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255
// short channel id: 0102030405060708
// fee base msat: 1
// fee proportional millionths 20
// cltv expiry delta: 3
foreach ($paymentRequest->findTagByName(\Jorijn\Bitcoin\Bolt11\Model\Tag::ROUTING_INFO)->getData() as $hop => $routingInfo) {
    echo 'hop: ' . $hop;
    echo 'public key: ' . $routingInfo->getPubKey();
    echo 'short channel id: ' . $routingInfo->getShortChannelId();
    echo 'fee base msat: ' . $routingInfo->getFeeBaseMsat();
    echo 'fee proportional millionths ' . $routingInfo->getFeeProportionalMillionths();
    echo 'cltv expiry delta: ' . $routingInfo->getCltvExpiryDelta();
}
```

More examples are available in the [examples](examples) directory.

### Fields that appear more than once

An invoice can carry several routing hints (`r`) and fallback addresses (`f`). `findTagByName()` returns only the first; `findTagsByName()` returns all of them, in invoice order:

```php
foreach ($paymentRequest->findTagsByName(\Jorijn\Bitcoin\Bolt11\Model\Tag::FALLBACK_ADDRESS) as $tag) {
    echo 'fallback address: ' . $tag->getData()->getAddress();
}
```

### Handling invalid invoices

Every invoice that cannot be decoded throws a `\Jorijn\Bitcoin\Bolt11\Exception\PaymentRequestDecodeException` (or a subclass), so one `catch` is enough when you decode input from outside:

```php
try {
    $paymentRequest = $denormalizer->denormalize($decoder->decode($invoice));
} catch (\Jorijn\Bitcoin\Bolt11\Exception\PaymentRequestDecodeException $exception) {
    // not a valid BOLT #11 invoice
}
```

## Networks

| Prefix   | Network | `getNetwork()` returns                             |
|----------|---------|----------------------------------------------------|
| `lnbc`   | mainnet | `BitWasp\Bitcoin\Network\Networks\Bitcoin`          |
| `lntb`   | testnet | `BitWasp\Bitcoin\Network\Networks\BitcoinTestnet`   |
| `lntbs`  | signet  | `Jorijn\Bitcoin\Bolt11\Network\BitcoinSignet`        |
| `lnbcrt` | regtest | `Jorijn\Bitcoin\Bolt11\Network\BitcoinRegtest`       |

Signet is deliberately not a subclass of `BitcoinTestnet`, even though its addresses look the same: coins on one network do not exist on the other. The regtest class extends the one from `bitwasp/bitcoin`, but encodes fallback addresses with the `bcrt` prefix that Bitcoin Core uses on regtest.

## Warning

`->getSatoshis()` truncates to whole satoshis: an invoice for 1500 millisatoshis returns `1`. Use `->getMilliSatoshis()` when you need the exact amount; 1000 millisatoshis is 1 satoshi. Both return `null` for an invoice without an amount.

## Contributing and releases

Releases are automated with [release-please](https://github.com/googleapis/release-please). It reads the commit messages on `master`, so they follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/). The type decides whether a commit ends up in a release:

| Commit message                                                     | Effect                                         |
|--------------------------------------------------------------------|------------------------------------------------|
| `fix: reject invoices with an empty f field`                       | patch release (1.1.0 → 1.1.1), under Bug Fixes |
| `feat: decode BOLT 12 offers`                                      | minor release (1.1.0 → 1.2.0), under Features  |
| `feat!: require PHP 8.3`, or a `BREAKING CHANGE:` footer           | major release (1.x → 2.0.0)                    |
| `deps: allow protonlabs/bitcoin ^2.0`                              | patch release, under Dependencies              |
| `docs:`, `test:`, `ci:`, `build:`, `chore:`, `refactor:`, `style:` | no release, not in the changelog               |

After each push to `master`, release-please keeps one open pull request up to date with the next version and its CHANGELOG entry. Merging that pull request tags the version, publishes the GitHub release, and Packagist picks up the tag.

## Thanks

This library is based on other BOLT #11 libraries from other programming languages. Special thanks to:

* https://github.com/lightningnetwork/lnd/blob/master/zpay32/decode.go
* https://github.com/bitcoinjs/bolt11
* https://github.com/nievk/bolt11

## CLI tool

There is a CLI tool based on this library. It allows for easy decoding and converting of payment requests into JSON, XML, YAML & CSV. Download and usage here: https://github.com/Jorijn/bitcoin-bolt11-cli
