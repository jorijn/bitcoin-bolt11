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

namespace Jorijn\Bitcoin\Bolt11\Model;

/**
 * A decoded and verified BOLT #11 payment request.
 *
 * Immutable: every value comes from the signed invoice, so nothing here can
 * change without invalidating the signature. Hex strings are lowercase.
 */
final readonly class PaymentRequest implements \JsonSerializable
{
    /** Expiry in seconds when the invoice has no `x` field. */
    public const DEFAULT_EXPIRY = 3600;

    /** min_final_cltv_expiry_delta when the invoice has no `c` field. */
    public const DEFAULT_MIN_FINAL_CLTV_EXPIRY_DELTA = 18;

    /**
     * @param string                $prefix            the human-readable part, lowercase: "lnbc2500u"
     * @param ?int                  $milliSatoshis     null for an invoice without an amount
     * @param string                $payeeNodeKey      hex, 33 bytes: from the `n` field, or recovered from the signature
     * @param string                $signature         hex, 64 bytes: r || s
     * @param string                $paymentHash       hex, 32 bytes (`p` field)
     * @param ?string               $paymentSecret     hex, 32 bytes (`s` field); only null in lenient mode
     * @param ?string               $description       UTF-8 (`d` field)
     * @param ?string               $descriptionHash   hex, 32 bytes: SHA-256 of a description passed some other way (`h` field)
     * @param int                   $expiry            seconds after the timestamp (`x` field)
     * @param ?string               $metadata          hex (`m` field), to pass along as payment_metadata
     * @param list<FallbackAddress> $fallbackAddresses most preferred first
     * @param list<RouteHint>       $routeHints        most preferred first
     * @param list<UnknownField>    $unknownFields     tagged fields this library does not interpret
     */
    public function __construct(
        private string $prefix,
        private Network $network,
        private ?int $milliSatoshis,
        private \DateTimeImmutable $timestamp,
        private string $payeeNodeKey,
        private string $signature,
        private int $recoveryFlag,
        private string $paymentHash,
        private ?string $paymentSecret = null,
        private ?string $description = null,
        private ?string $descriptionHash = null,
        private int $expiry = self::DEFAULT_EXPIRY,
        private int $minFinalCltvExpiryDelta = self::DEFAULT_MIN_FINAL_CLTV_EXPIRY_DELTA,
        private ?string $metadata = null,
        private Features $features = new Features(),
        private array $fallbackAddresses = [],
        private array $routeHints = [],
        private array $unknownFields = [],
    ) {}

    public function getPrefix(): string
    {
        return $this->prefix;
    }

    public function getNetwork(): Network
    {
        return $this->network;
    }

    /**
     * The amount in millisatoshis, the unit Lightning pays in. Null when the
     * invoice leaves the amount to the payer (a donation, for example).
     */
    public function getMilliSatoshis(): ?int
    {
        return $this->milliSatoshis;
    }

    /**
     * The amount in whole satoshis, rounded down: an invoice for 1500
     * millisatoshis returns 1. Use getMilliSatoshis() for the exact amount.
     */
    public function getSatoshis(): ?int
    {
        return null === $this->milliSatoshis ? null : intdiv($this->milliSatoshis, 1000);
    }

    /**
     * When the invoice was created, in UTC.
     */
    public function getTimestamp(): \DateTimeImmutable
    {
        return $this->timestamp;
    }

    /**
     * Seconds after the timestamp until the invoice expires.
     */
    public function getExpiry(): int
    {
        return $this->expiry;
    }

    /**
     * The moment the invoice expires, in UTC; after it, BOLT #11 says the
     * payer should not pay and the payee should not accept.
     */
    public function getExpiresAt(): \DateTimeImmutable
    {
        return new \DateTimeImmutable('@'.($this->timestamp->getTimestamp() + $this->expiry));
    }

    public function isExpired(?\DateTimeInterface $now = null): bool
    {
        return ($now ?? new \DateTimeImmutable())->getTimestamp() >= $this->getExpiresAt()->getTimestamp();
    }

    /**
     * The payee's public key, hex encoded: the node to pay.
     */
    public function getPayeeNodeKey(): string
    {
        return $this->payeeNodeKey;
    }

    /**
     * The signature, hex encoded: 32 bytes r followed by 32 bytes s.
     */
    public function getSignature(): string
    {
        return $this->signature;
    }

    public function getRecoveryFlag(): int
    {
        return $this->recoveryFlag;
    }

    /**
     * The hash whose preimage is the proof of payment, hex encoded.
     */
    public function getPaymentHash(): string
    {
        return $this->paymentHash;
    }

    /**
     * The payment secret, hex encoded. Only null for an invoice decoded in
     * lenient mode; strict mode rejects an invoice without one.
     */
    public function getPaymentSecret(): ?string
    {
        return $this->paymentSecret;
    }

    /**
     * The description, if the invoice has one inline.
     *
     * It comes from whoever made the invoice: escape it before you show it in
     * HTML or put it in a query. In lenient mode it may not be valid UTF-8.
     */
    public function getDescription(): ?string
    {
        return $this->description;
    }

    /**
     * The SHA-256 of a description that was passed some other way, hex encoded.
     */
    public function getDescriptionHash(): ?string
    {
        return $this->descriptionHash;
    }

    /**
     * Whether a description matches the description hash (`h` field).
     * BOLT #11 requires this check before paying an invoice that has one.
     * False when the invoice has no description hash.
     */
    public function verifyDescriptionHash(string $description): bool
    {
        return null !== $this->descriptionHash && hash_equals($this->descriptionHash, hash('sha256', $description));
    }

    public function getMinFinalCltvExpiryDelta(): int
    {
        return $this->minFinalCltvExpiryDelta;
    }

    /**
     * Payment metadata (`m` field), hex encoded: the payer must pass it along
     * as payment_metadata.
     */
    public function getMetadata(): ?string
    {
        return $this->metadata;
    }

    public function getFeatures(): Features
    {
        return $this->features;
    }

    /**
     * On-chain addresses to fall back to, most preferred first. Addresses with
     * a version this library does not know are left out, as BOLT #11 requires.
     *
     * @return list<FallbackAddress>
     */
    public function getFallbackAddresses(): array
    {
        return $this->fallbackAddresses;
    }

    /**
     * Private routes to the payee, most preferred first.
     *
     * @return list<RouteHint>
     */
    public function getRouteHints(): array
    {
        return $this->routeHints;
    }

    /**
     * Tagged fields this library does not interpret.
     *
     * @return list<UnknownField>
     */
    public function getUnknownFields(): array
    {
        return $this->unknownFields;
    }

    /**
     * Every value as plain PHP data: scalars, null and nested arrays. Times are
     * Unix timestamps. The keys are part of the backward compatibility promise.
     *
     * @return array{
     *     prefix: string,
     *     network: string,
     *     milli_satoshis: ?int,
     *     satoshis: ?int,
     *     timestamp: int,
     *     expiry: int,
     *     expiry_timestamp: int,
     *     payee_node_key: string,
     *     signature: string,
     *     recovery_flag: int,
     *     payment_hash: string,
     *     payment_secret: ?string,
     *     description: ?string,
     *     description_hash: ?string,
     *     min_final_cltv_expiry_delta: int,
     *     metadata: ?string,
     *     features: list<int>,
     *     fallback_addresses: list<array{version: int, program: string, address: string}>,
     *     route_hints: list<list<array{public_key: string, short_channel_id: string, fee_base_msat: int, fee_proportional_millionths: int, cltv_expiry_delta: int}>>,
     *     unknown_fields: list<array{type: int, words: list<int>}>,
     * }
     */
    public function toArray(): array
    {
        return [
            'prefix' => $this->prefix,
            'network' => $this->network->value,
            'milli_satoshis' => $this->milliSatoshis,
            'satoshis' => $this->getSatoshis(),
            'timestamp' => $this->timestamp->getTimestamp(),
            'expiry' => $this->expiry,
            'expiry_timestamp' => $this->getExpiresAt()->getTimestamp(),
            'payee_node_key' => $this->payeeNodeKey,
            'signature' => $this->signature,
            'recovery_flag' => $this->recoveryFlag,
            'payment_hash' => $this->paymentHash,
            'payment_secret' => $this->paymentSecret,
            'description' => $this->description,
            'description_hash' => $this->descriptionHash,
            'min_final_cltv_expiry_delta' => $this->minFinalCltvExpiryDelta,
            'metadata' => $this->metadata,
            'features' => $this->features->getBits(),
            'fallback_addresses' => array_map(static fn (FallbackAddress $address): array => $address->toArray(), $this->fallbackAddresses),
            'route_hints' => array_map(static fn (RouteHint $hint): array => $hint->toArray(), $this->routeHints),
            'unknown_fields' => array_map(static fn (UnknownField $field): array => $field->toArray(), $this->unknownFields),
        ];
    }

    /**
     * @return array<string, mixed> the same as toArray()
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
