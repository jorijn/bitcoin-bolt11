<?php

declare(strict_types=1);

/*
 * This file is part of the PHP Bitcoin BOLT11 package.
 *
 * (c) Jorijn Schrijvershof <jorijn@jorijn.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Jorijn\Bitcoin\Bolt11;

use Jorijn\Bitcoin\Bolt11\Exception\InvalidAmountException;
use Jorijn\Bitcoin\Bolt11\Exception\InvalidPaymentRequestException;
use Jorijn\Bitcoin\Bolt11\Exception\PaymentRequestDecodeException;
use Jorijn\Bitcoin\Bolt11\Exception\SignatureDoesNotMatchPayeePubkeyDecodeException;
use Jorijn\Bitcoin\Bolt11\Exception\SignatureIncorrectOrMissingException;
use Jorijn\Bitcoin\Bolt11\Exception\UnableToDecodeBech32Exception;
use Jorijn\Bitcoin\Bolt11\Exception\UnknownNetworkVersionException;
use Jorijn\Bitcoin\Bolt11\Exception\UnknownRequiredFeatureException;
use Jorijn\Bitcoin\Bolt11\Exception\UnrecoverableSignatureException;
use Jorijn\Bitcoin\Bolt11\Internal\Base58;
use Jorijn\Bitcoin\Bolt11\Internal\Bech32;
use Jorijn\Bitcoin\Bolt11\Internal\Secp256k1;
use Jorijn\Bitcoin\Bolt11\Model\FallbackAddress;
use Jorijn\Bitcoin\Bolt11\Model\Features;
use Jorijn\Bitcoin\Bolt11\Model\Network;
use Jorijn\Bitcoin\Bolt11\Model\PaymentRequest;
use Jorijn\Bitcoin\Bolt11\Model\RouteHint;
use Jorijn\Bitcoin\Bolt11\Model\RouteHintHop;
use Jorijn\Bitcoin\Bolt11\Model\UnknownField;

/**
 * Decodes BOLT #11 payment requests and verifies their signature.
 *
 * Strict by default: it rejects every invoice the specification tells a
 * reader to reject. Pass lenient: true to read invoices from before those
 * rules, such as ones without a payment secret; see the README for exactly
 * which checks that relaxes. Checks that protect the payer, such as the
 * checksum, the signature and the amount, are never relaxed.
 *
 * @see https://github.com/lightning/bolts/blob/master/11-payment-encoding.md
 */
final class PaymentRequestDecoder implements PaymentRequestDecoderInterface
{
    private const TIMESTAMP_WORDS = 7;
    private const SIGNATURE_WORDS = 104;

    private const FIELD_PAYMENT_HASH = 1;
    private const FIELD_ROUTE_HINT = 3;
    private const FIELD_FEATURES = 5;
    private const FIELD_EXPIRY = 6;
    private const FIELD_FALLBACK_ADDRESS = 9;
    private const FIELD_DESCRIPTION = 13;
    private const FIELD_PAYMENT_SECRET = 16;
    private const FIELD_PAYEE_NODE_KEY = 19;
    private const FIELD_DESCRIPTION_HASH = 23;
    private const FIELD_MIN_FINAL_CLTV_EXPIRY = 24;
    private const FIELD_METADATA = 27;

    /** 32-byte hashes take 52 words, a 33-byte public key 53. */
    private const FIXED_LENGTHS = [
        self::FIELD_PAYMENT_HASH => 52,
        self::FIELD_PAYMENT_SECRET => 52,
        self::FIELD_DESCRIPTION_HASH => 52,
        self::FIELD_PAYEE_NODE_KEY => 53,
    ];

    /** Millisatoshis per unit of each multiplier, as a power of ten: 1 BTC is 10^11 msat. */
    private const MULTIPLIER_EXPONENTS = ['' => 11, 'm' => 8, 'u' => 5, 'n' => 2, 'p' => -1];

    /** 21 million bitcoin; anything above is not an amount anyone can pay. */
    private const MAX_MILLI_SATOSHIS = 2_100_000_000_000_000_000;

    /** 9999-12-31T23:59:59Z: an expiry beyond it does not fit a four-digit year. */
    private const MAX_EXPIRY_TIMESTAMP = 253_402_300_799;

    /** Each hop of a route hint: pubkey (33), short_channel_id (8), fee_base_msat (4), fee_proportional_millionths (4), cltv_expiry_delta (2). */
    private const ROUTE_HINT_HOP_BYTES = 51;

    /**
     * @param bool $lenient accept invoices that break the rules a reader must enforce
     *                      but that older writers did not follow; see the README
     */
    public function __construct(private readonly bool $lenient = false) {}

    public function decode(string $paymentRequest): PaymentRequest
    {
        try {
            return $this->decodePaymentRequest($paymentRequest);
        } catch (PaymentRequestDecodeException $exception) {
            throw $exception;
        } catch (\Throwable $exception) {
            // Safety net. Every failure we know of has its own exception above,
            // but the input comes from outside, and callers rely on a single
            // catch for it. The original stays available as the previous one.
            throw new InvalidPaymentRequestException('unable to decode payment request: '.$exception->getMessage(), 0, $exception);
        }
    }

    private function decodePaymentRequest(string $paymentRequest): PaymentRequest
    {
        try {
            // BOLT #11 lifts the 90-character limit of BIP 173: invoices with
            // routing hints are usually longer.
            [$humanReadablePart, $words] = Bech32::decode($paymentRequest);
        } catch (\InvalidArgumentException $exception) {
            throw new UnableToDecodeBech32Exception($exception->getMessage(), 0, $exception);
        }

        [$network, $milliSatoshis] = $this->parseHumanReadablePart($humanReadablePart);

        if (\count($words) < self::TIMESTAMP_WORDS + self::SIGNATURE_WORDS) {
            throw new SignatureIncorrectOrMissingException('payment request is too short to hold a timestamp and a signature');
        }

        // The signature is always the last 104 words: 64 bytes r || s and one
        // byte recovery id, 520 bits without padding.
        $dataWords = \array_slice($words, 0, -self::SIGNATURE_WORDS);
        $signatureBytes = Bech32::wordsToBytes(\array_slice($words, -self::SIGNATURE_WORDS));
        $signature = substr($signatureBytes, 0, 64);
        $recoveryFlag = \ord($signatureBytes[64]);
        if ($recoveryFlag > 3) {
            throw new SignatureIncorrectOrMissingException('signature recovery id must be between 0 and 3');
        }

        $timestamp = $this->wordsToInt(\array_slice($dataWords, 0, self::TIMESTAMP_WORDS));
        $fields = $this->parseTaggedFields(\array_slice($dataWords, self::TIMESTAMP_WORDS), $network);

        // The signature covers the human-readable part as text, then the data
        // words (without the signature) padded with zero bits to whole bytes.
        $hash = hash('sha256', $humanReadablePart.Bech32::wordsToBytes($dataWords, true), true);
        $payeeNodeKey = $this->verifySignature($hash, $signature, $recoveryFlag, $fields['payeeNodeKey']);

        if ($fields['expiry'] > self::MAX_EXPIRY_TIMESTAMP - $timestamp) {
            throw new InvalidPaymentRequestException('expiry time is out of range');
        }

        return new PaymentRequest(
            prefix: $humanReadablePart,
            network: $network,
            milliSatoshis: $milliSatoshis,
            timestamp: new \DateTimeImmutable('@'.$timestamp),
            payeeNodeKey: $payeeNodeKey,
            signature: bin2hex($signature),
            recoveryFlag: $recoveryFlag,
            paymentHash: $fields['paymentHash'],
            paymentSecret: $fields['paymentSecret'],
            description: $fields['description'],
            descriptionHash: $fields['descriptionHash'],
            expiry: $fields['expiry'],
            minFinalCltvExpiryDelta: $fields['minFinalCltvExpiryDelta'],
            metadata: $fields['metadata'],
            features: $fields['features'],
            fallbackAddresses: $fields['fallbackAddresses'],
            routeHints: $fields['routeHints'],
            unknownFields: $fields['unknownFields'],
        );
    }

    /**
     * "lnbc2500u" is "ln", the currency "bc" and the amount "2500u".
     *
     * @return array{Network, ?int} the network and the amount in millisatoshis
     */
    private function parseHumanReadablePart(string $humanReadablePart): array
    {
        if (!str_starts_with($humanReadablePart, 'ln')) {
            throw new InvalidPaymentRequestException('data does not appear to be a bolt11 invoice');
        }

        // The currency is letters only and an amount starts with a digit, so
        // the first digit is where the currency ends: "lnbcrt1m" is regtest,
        // "lnbc1m" mainnet. Matching known prefixes instead would read "lnbc0"
        // as an unknown currency "bc0" or "lnbcrt" as "bc" plus junk.
        if (1 !== preg_match('/^ln([a-z]+)(.*)$/', $humanReadablePart, $matches)) {
            throw new UnknownNetworkVersionException('payment request has no currency prefix');
        }

        $network = Network::tryFrom($matches[1]);
        if (null === $network) {
            throw new UnknownNetworkVersionException(\sprintf('unknown network "%s" for invoice', $matches[1]));
        }

        if ('' === $matches[2]) {
            return [$network, null];
        }

        return [$network, $this->parseAmount($matches[2])];
    }

    private function parseAmount(string $amount): int
    {
        if (1 !== preg_match('/^(\d+)([munp]?)$/', $amount, $matches)) {
            throw new InvalidAmountException('not a valid amount or multiplier');
        }

        // A writer must not use leading zeros. "lnbc0" and "lnbc00" are not
        // amounts anyone meant, and an amount of zero is not a payment request.
        if ('0' === $matches[1][0]) {
            throw new InvalidAmountException('amount must be a positive number without leading zeros');
        }

        // An amount can have more digits than fit in an int before it is
        // rejected as too large, so compute it with GMP.
        $exponent = self::MULTIPLIER_EXPONENTS[$matches[2]];
        $milliSatoshis = gmp_init($matches[1], 10);
        if ($exponent >= 0) {
            $milliSatoshis *= gmp_pow(10, $exponent);
        } else {
            // 1p is a tenth of a millisatoshi, which no one can pay.
            if (0 !== gmp_sign(gmp_mod($milliSatoshis, 10))) {
                throw new InvalidAmountException('amount is not a whole number of millisatoshis');
            }

            $milliSatoshis = gmp_div_q($milliSatoshis, 10);
        }

        if (gmp_cmp($milliSatoshis, self::MAX_MILLI_SATOSHIS) > 0) {
            throw new InvalidAmountException('amount is more than 21 million bitcoin');
        }

        return gmp_intval($milliSatoshis);
    }

    /**
     * Reads the tagged fields: 5 bits type, 10 bits length in words, then data.
     *
     * When a field appears more than once, the writer puts its preferred one
     * first, so the first one wins. Strict mode rejects duplicates only where
     * BOLT #11 says there must be exactly one (`p`, `s`, `d` or `h`).
     *
     * @param list<int> $words
     *
     * @return array{
     *     paymentHash: string,
     *     paymentSecret: ?string,
     *     description: ?string,
     *     descriptionHash: ?string,
     *     payeeNodeKey: ?string,
     *     expiry: int,
     *     minFinalCltvExpiryDelta: int,
     *     metadata: ?string,
     *     features: Features,
     *     fallbackAddresses: list<FallbackAddress>,
     *     routeHints: list<RouteHint>,
     *     unknownFields: list<UnknownField>,
     * }
     */
    private function parseTaggedFields(array $words, Network $network): array
    {
        /** @var array<int, list<list<int>>> $known the data of each known field, by type */
        $known = [];
        $fallbackAddresses = [];
        $routeHints = [];
        $unknownFields = [];

        $position = 0;
        $count = \count($words);
        while ($position < $count) {
            if ($position + 3 > $count) {
                throw new InvalidPaymentRequestException('tagged field is truncated');
            }

            $type = $words[$position];
            $length = ($words[$position + 1] << 5) | $words[$position + 2];
            $position += 3;
            if ($position + $length > $count) {
                throw new InvalidPaymentRequestException('tagged field is longer than the payment request');
            }

            $data = \array_slice($words, $position, $length);
            $position += $length;

            if (isset(self::FIXED_LENGTHS[$type]) && self::FIXED_LENGTHS[$type] !== $length) {
                // Older versions of BOLT #11 told readers to skip these; now
                // they must reject the invoice (spec vector 17).
                $this->violation(\sprintf('field of type %d must be %d words long, not %d', $type, self::FIXED_LENGTHS[$type], $length));

                continue;
            }

            switch ($type) {
                case self::FIELD_FALLBACK_ADDRESS:
                    $address = $this->parseFallbackAddress($data, $network);
                    if (null !== $address) {
                        $fallbackAddresses[] = $address;
                    }

                    break;

                case self::FIELD_ROUTE_HINT:
                    $routeHint = $this->parseRouteHint($data);
                    if (null !== $routeHint) {
                        $routeHints[] = $routeHint;
                    }

                    break;

                case self::FIELD_PAYMENT_HASH:
                case self::FIELD_PAYMENT_SECRET:
                case self::FIELD_DESCRIPTION:
                case self::FIELD_DESCRIPTION_HASH:
                case self::FIELD_PAYEE_NODE_KEY:
                case self::FIELD_EXPIRY:
                case self::FIELD_MIN_FINAL_CLTV_EXPIRY:
                case self::FIELD_FEATURES:
                case self::FIELD_METADATA:
                    $known[$type][] = $data;

                    break;

                default:
                    $unknownFields[] = new UnknownField($type, $data);
            }
        }

        $paymentHashes = $known[self::FIELD_PAYMENT_HASH] ?? [];
        $paymentSecrets = $known[self::FIELD_PAYMENT_SECRET] ?? [];
        $descriptions = $known[self::FIELD_DESCRIPTION] ?? [];
        $descriptionHashes = $known[self::FIELD_DESCRIPTION_HASH] ?? [];

        // Never relaxed: without a payment hash there is nothing to pay.
        if ([] === $paymentHashes) {
            throw new InvalidPaymentRequestException('payment request has no payment hash (p)');
        }

        // Exactly one, so different components cannot pick a different hash or
        // secret from the same signed invoice.
        if (\count($paymentHashes) > 1) {
            $this->violation('payment request has more than one payment hash (p)');
        }

        if (1 !== \count($paymentSecrets)) {
            $this->violation([] === $paymentSecrets
                ? 'payment request has no payment secret (s)'
                : 'payment request has more than one payment secret (s)');
        }

        if (1 !== \count($descriptions) + \count($descriptionHashes)) {
            $this->violation('payment request must have either one description (d) or one description hash (h)');
        }

        $description = isset($descriptions[0]) ? Bech32::wordsToBytes($descriptions[0]) : null;
        if (null !== $description && !$this->isValidDescription($description)) {
            $this->violation('description (d) is not valid UTF-8 or contains control characters');
        }

        $payeeNodeKey = null;
        if (isset($known[self::FIELD_PAYEE_NODE_KEY][0])) {
            $payeeNodeKey = Bech32::wordsToBytes($known[self::FIELD_PAYEE_NODE_KEY][0]);
            if (!Secp256k1::isValidPublicKey($payeeNodeKey)) {
                // Lenient: ignore it and fall back to public-key recovery.
                $this->violation('payee node key (n) is not a valid public key');
                $payeeNodeKey = null;
            }
        }

        return [
            'paymentHash' => bin2hex(Bech32::wordsToBytes($paymentHashes[0])),
            'paymentSecret' => isset($paymentSecrets[0]) ? bin2hex(Bech32::wordsToBytes($paymentSecrets[0])) : null,
            'description' => $description,
            'descriptionHash' => isset($descriptionHashes[0]) ? bin2hex(Bech32::wordsToBytes($descriptionHashes[0])) : null,
            'payeeNodeKey' => $payeeNodeKey,
            'expiry' => $this->parseInteger($known[self::FIELD_EXPIRY][0] ?? null, PaymentRequest::DEFAULT_EXPIRY, 'expiry (x)'),
            'minFinalCltvExpiryDelta' => $this->parseInteger($known[self::FIELD_MIN_FINAL_CLTV_EXPIRY][0] ?? null, PaymentRequest::DEFAULT_MIN_FINAL_CLTV_EXPIRY_DELTA, 'min_final_cltv_expiry_delta (c)'),
            'metadata' => isset($known[self::FIELD_METADATA][0]) ? bin2hex(Bech32::wordsToBytes($known[self::FIELD_METADATA][0])) : null,
            'features' => $this->parseFeatures($known[self::FIELD_FEATURES][0] ?? null),
            'fallbackAddresses' => $fallbackAddresses,
            'routeHints' => $routeHints,
            'unknownFields' => $unknownFields,
        ];
    }

    /**
     * @param ?list<int> $words null when the field is absent
     */
    private function parseInteger(?array $words, int $default, string $name): int
    {
        if (null === $words) {
            return $default;
        }

        if ([] !== $words && 0 === $words[0]) {
            $this->violation(\sprintf('%s has leading zeros', $name));
        }

        return $this->wordsToInt($words);
    }

    /**
     * @param ?list<int> $words null when the field is absent
     */
    private function parseFeatures(?array $words): Features
    {
        if (null === $words) {
            return new Features();
        }

        if ([] !== $words && 0 === $words[0]) {
            $this->violation('features (9) have leading zeros');
        }

        // Big-endian: bit 0 is the lowest bit of the last word.
        $bits = [];
        $last = \count($words) - 1;
        foreach ($words as $index => $word) {
            for ($bit = 0; $bit < 5; ++$bit) {
                if (0 !== ($word & (1 << $bit))) {
                    $bits[] = ($last - $index) * 5 + $bit;
                }
            }
        }

        $features = new Features($bits);
        if ($this->lenient) {
            return $features;
        }

        // It's OK to be odd: an unknown odd bit is optional and ignored, an
        // unknown even bit is required, and then the payer must not pay.
        $unknown = $features->getUnknownRequiredBits();
        if ([] !== $unknown) {
            throw new UnknownRequiredFeatureException(\sprintf('payment request requires unknown feature bits: %s', implode(', ', $unknown)), $unknown);
        }

        // BOLT #9 dependency: basic_mpp needs payment_secret.
        if ($features->supports(Features::BASIC_MPP) && !$features->supports(Features::PAYMENT_SECRET)) {
            throw new UnknownRequiredFeatureException('feature basic_mpp requires feature payment_secret', [Features::PAYMENT_SECRET]);
        }

        return $features;
    }

    /**
     * @param list<int> $words
     */
    private function parseFallbackAddress(array $words, Network $network): ?FallbackAddress
    {
        if ([] === $words) {
            $this->violation('fallback address (f) field is empty');

            return null;
        }

        $version = $words[0];
        if ($version > FallbackAddress::VERSION_P2SH) {
            // A reader must skip versions it does not know (19 to 31).
            return null;
        }

        $program = Bech32::wordsToBytes(\array_slice($words, 1));

        try {
            $address = match ($version) {
                FallbackAddress::VERSION_P2PKH => $this->encodeBase58Address($network->p2pkhVersion(), $program),
                FallbackAddress::VERSION_P2SH => $this->encodeBase58Address($network->p2shVersion(), $program),
                default => Bech32::encodeSegwitAddress($network->segwitPrefix(), $version, $program),
            };
        } catch (\InvalidArgumentException $exception) {
            $this->violation('fallback address (f) field is invalid: '.$exception->getMessage());

            return null;
        }

        return new FallbackAddress($version, bin2hex($program), $address);
    }

    private function encodeBase58Address(int $version, string $hash): string
    {
        if (20 !== \strlen($hash)) {
            throw new \InvalidArgumentException(\sprintf('a P2PKH or P2SH hash is 20 bytes, not %d', \strlen($hash)));
        }

        return Base58::encodeCheck($version, $hash);
    }

    /**
     * @param list<int> $words
     */
    private function parseRouteHint(array $words): ?RouteHint
    {
        $bytes = Bech32::wordsToBytes($words);
        if ('' === $bytes || 0 !== \strlen($bytes) % self::ROUTE_HINT_HOP_BYTES) {
            $this->violation('routing info (r) field has an invalid length');

            return null;
        }

        $hops = [];
        foreach (str_split($bytes, self::ROUTE_HINT_HOP_BYTES) as $hop) {
            /** @var array{feeBase: int, feeProportional: int, cltvExpiryDelta: int} $numbers */
            $numbers = unpack('NfeeBase/NfeeProportional/ncltvExpiryDelta', $hop, 41);
            $hops[] = new RouteHintHop(
                bin2hex(substr($hop, 0, 33)),
                bin2hex(substr($hop, 33, 8)),
                $numbers['feeBase'],
                $numbers['feeProportional'],
                $numbers['cltvExpiryDelta'],
            );
        }

        return new RouteHint($hops);
    }

    /**
     * BOLT #1: valid UTF-8 without control, format, surrogate or private-use
     * characters, or line and paragraph separators. These can hide text from
     * the user or change how the rest of the description reads.
     */
    private function isValidDescription(string $description): bool
    {
        // preg_match() returns false, not 1, on invalid UTF-8 with the u flag.
        return 0 === preg_match('/[\p{Cc}\p{Cf}\p{Cs}\p{Co}\x{2028}\x{2029}]/u', $description);
    }

    /**
     * @return string the payee's public key, hex encoded
     */
    private function verifySignature(string $hash, string $signature, int $recoveryFlag, ?string $payeeNodeKey): string
    {
        if (null !== $payeeNodeKey) {
            // With an `n` field the reader must verify against it instead of
            // recovering the key, and reject high-S signatures: both
            // (r, s) and (r, n - s) verify, so accepting either would make the
            // invoice malleable (spec vector 30).
            if (!Secp256k1::isLowS($signature)) {
                $this->violation('signature is not in low-S form', SignatureIncorrectOrMissingException::class);
            }

            if (!Secp256k1::verify($hash, $signature, $payeeNodeKey)) {
                throw new SignatureDoesNotMatchPayeePubkeyDecodeException('lightning payment request signature pubkey does not match payee pubkey');
            }

            return bin2hex($payeeNodeKey);
        }

        // Without `n`, recovery must accept both high-S and low-S (vector 15).
        try {
            return bin2hex(Secp256k1::recoverPublicKey($hash, $signature, $recoveryFlag));
        } catch (\InvalidArgumentException $exception) {
            throw new UnrecoverableSignatureException('unable to recover signature from signed message: '.$exception->getMessage(), 0, $exception);
        }
    }

    /**
     * Big-endian, five bits per word. BOLT #11 puts no upper bound on `x` or
     * `c`, so a value that does not fit in an int is rejected, never relaxed.
     *
     * @param list<int> $words
     */
    private function wordsToInt(array $words): int
    {
        $value = 0;
        foreach ($words as $word) {
            if ($value > (PHP_INT_MAX >> 5)) {
                throw new InvalidPaymentRequestException('integer field is too large');
            }

            $value = ($value << 5) | $word;
        }

        return $value;
    }

    /**
     * A rule that strict mode enforces and lenient mode lets pass.
     *
     * @param class-string<PaymentRequestDecodeException> $exceptionClass
     */
    private function violation(string $message, string $exceptionClass = InvalidPaymentRequestException::class): void
    {
        if (!$this->lenient) {
            throw new $exceptionClass($message);
        }
    }
}
