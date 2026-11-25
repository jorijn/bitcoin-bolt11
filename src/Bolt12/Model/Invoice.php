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

namespace Jorijn\Bitcoin\Bolt12\Model;

/**
 * A BOLT #12 invoice ("lni1..."): the answer to an invoice request, with
 * everything needed to pay it. It copies all fields of the request, and so
 * of the offer.
 *
 * Binary values (keys, hashes) are lowercase hex.
 *
 * @see https://github.com/lightning/bolts/blob/master/12-offer-encoding.md#invoices
 *
 * @phpstan-import-type InvoiceRequestArray from InvoiceRequest
 * @phpstan-import-type PaymentPathArray from PaymentPath
 *
 * @phpstan-type InvoiceArray array{invoice_request: InvoiceRequestArray, paths: list<PaymentPathArray>, created_at: string, relative_expiry: int, expires_at: string, payment_hash: string, amount: int, fallback_addresses: list<array{version: int, program: string, address: ?string}>, features: list<int>, node_id: string, signature: string, unknown_fields: list<array{type: int, value: string}>}
 */
final readonly class Invoice implements \JsonSerializable
{
    /** BOLT #12: an invoice without invoice_relative_expiry expires after two hours. */
    public const DEFAULT_RELATIVE_EXPIRY = 7200;

    /**
     * @param list<PaymentPath>     $paths
     * @param list<FallbackAddress> $fallbackAddresses
     * @param list<UnknownField>    $unknownFields     odd records in the invoice ranges this library does not know
     */
    public function __construct(
        private InvoiceRequest $invoiceRequest,
        private array $paths,
        private int $createdAt,
        private int $relativeExpiry,
        private string $paymentHash,
        private int $amount,
        private array $fallbackAddresses,
        private Features $features,
        private string $nodeId,
        private string $signature,
        private array $unknownFields,
    ) {}

    /**
     * The invoice request fields this invoice copied (without the request's
     * signature, which an invoice does not carry).
     */
    public function getInvoiceRequest(): InvoiceRequest
    {
        return $this->invoiceRequest;
    }

    /**
     * Shortcut for getInvoiceRequest()->getOffer().
     */
    public function getOffer(): Offer
    {
        return $this->invoiceRequest->getOffer();
    }

    /**
     * The chain to pay on, hex. Bitcoin unless the request named another.
     */
    public function getChain(): string
    {
        return $this->invoiceRequest->getChain();
    }

    /**
     * The blinded paths to pay through, most preferred first. Only the ones
     * for which isUsable() is true may be used.
     *
     * @return list<PaymentPath>
     */
    public function getPaths(): array
    {
        return $this->paths;
    }

    public function getCreatedAt(): \DateTimeImmutable
    {
        return (new \DateTimeImmutable('@0'))->setTimestamp($this->createdAt);
    }

    /**
     * Seconds after getCreatedAt() that the invoice expires.
     */
    public function getRelativeExpiry(): int
    {
        return $this->relativeExpiry;
    }

    public function getExpiresAt(): \DateTimeImmutable
    {
        return (new \DateTimeImmutable('@0'))->setTimestamp($this->createdAt + $this->relativeExpiry);
    }

    /**
     * A payer must not pay an expired invoice. The decoder does not reject
     * them, so they can still be inspected; check here before paying.
     */
    public function isExpired(?\DateTimeInterface $now = null): bool
    {
        return ($now ?? new \DateTimeImmutable())->getTimestamp() > $this->createdAt + $this->relativeExpiry;
    }

    /**
     * SHA-256 of the preimage the payer gets in return for paying, hex.
     */
    public function getPaymentHash(): string
    {
        return $this->paymentHash;
    }

    /**
     * The amount to pay, in millisatoshis.
     */
    public function getAmount(): int
    {
        return $this->amount;
    }

    /**
     * The amount in satoshis, rounded down.
     */
    public function getSatoshis(): int
    {
        return intdiv($this->amount, 1000);
    }

    /**
     * On-chain addresses to pay to instead, most preferred first. Entries the
     * specification tells a reader to ignore are left out.
     *
     * @return list<FallbackAddress>
     */
    public function getFallbackAddresses(): array
    {
        return $this->fallbackAddresses;
    }

    public function getFeatures(): Features
    {
        return $this->features;
    }

    /**
     * The key that signed the invoice, hex. For an offer with an issuer id it
     * is that id; for an offer with only blinded paths, the final blinded
     * node id of the path the request went through.
     */
    public function getNodeId(): string
    {
        return $this->nodeId;
    }

    /**
     * The BIP-340 signature, hex.
     */
    public function getSignature(): string
    {
        return $this->signature;
    }

    /**
     * @return list<UnknownField>
     */
    public function getUnknownFields(): array
    {
        return $this->unknownFields;
    }

    /**
     * Every field, with snake_case keys named after the specification.
     *
     * @return InvoiceArray
     */
    public function toArray(): array
    {
        return [
            'invoice_request' => $this->invoiceRequest->toArray(),
            'paths' => array_map(static fn (PaymentPath $path): array => $path->toArray(), $this->paths),
            'created_at' => $this->getCreatedAt()->format(\DateTimeInterface::ATOM),
            'relative_expiry' => $this->relativeExpiry,
            'expires_at' => $this->getExpiresAt()->format(\DateTimeInterface::ATOM),
            'payment_hash' => $this->paymentHash,
            'amount' => $this->amount,
            'fallback_addresses' => array_map(static fn (FallbackAddress $address): array => $address->toArray(), $this->fallbackAddresses),
            'features' => $this->features->getBits(),
            'node_id' => $this->nodeId,
            'signature' => $this->signature,
            'unknown_fields' => array_map(static fn (UnknownField $field): array => $field->toArray(), $this->unknownFields),
        ];
    }

    /**
     * @return InvoiceArray
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
