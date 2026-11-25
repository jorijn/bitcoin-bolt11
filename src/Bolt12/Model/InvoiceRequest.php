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
 * A BOLT #12 invoice request ("lnr1..."). It is either a payer's request for
 * an invoice for an offer, with all the offer's fields copied in, or a
 * request without an offer in which the sender offers to pay (a refund or
 * an ATM withdrawal, say).
 *
 * Invoices copy every invoice request field too: Invoice::getInvoiceRequest()
 * returns this class, without a signature, because the invoice's own
 * signature covers the copied fields.
 *
 * Binary values (keys, hashes, metadata) are lowercase hex.
 *
 * @see https://github.com/lightning/bolts/blob/master/12-offer-encoding.md#invoice-requests
 *
 * @phpstan-import-type OfferArray from Offer
 * @phpstan-import-type BlindedPathArray from BlindedPath
 *
 * @phpstan-type InvoiceRequestArray array{offer: OfferArray, metadata: string, chain: string, amount: ?int, features: list<int>, quantity: ?int, payer_id: string, payer_note: ?string, paths: list<BlindedPathArray>, bip_353_name: ?string, signature: ?string, unknown_fields: list<array{type: int, value: string}>}
 */
final readonly class InvoiceRequest implements \JsonSerializable
{
    /**
     * @param list<BlindedPath>  $paths
     * @param list<UnknownField> $unknownFields odd records in the invoice request ranges this library does not know
     */
    public function __construct(
        private Offer $offer,
        private string $metadata,
        private ?string $chain,
        private ?int $amount,
        private Features $features,
        private ?int $quantity,
        private string $payerId,
        private ?string $payerNote,
        private array $paths,
        private ?string $bip353Name,
        private ?string $signature,
        private array $unknownFields,
    ) {}

    /**
     * The offer fields. For a request without an offer these are the fields
     * the sender filled in itself: a description and perhaps an issuer.
     */
    public function getOffer(): Offer
    {
        return $this->offer;
    }

    /**
     * Whether this answers an offer (it carries the offer's issuer id or
     * paths) rather than offering to send money on its own.
     */
    public function isForOffer(): bool
    {
        return null !== $this->offer->getIssuerId() || [] !== $this->offer->getPaths();
    }

    /**
     * Random bytes the payer chose (invreq_metadata), hex encoded. They make
     * each request unique and its merkle leaves unguessable.
     */
    public function getMetadata(): string
    {
        return $this->metadata;
    }

    /**
     * The chain to pay on, hex. Bitcoin when the field is absent.
     */
    public function getChain(): string
    {
        return $this->chain ?? Chain::BITCOIN;
    }

    /**
     * The amount the payer will pay, in millisatoshis, or null to pay what
     * the offer asks.
     */
    public function getAmount(): ?int
    {
        return $this->amount;
    }

    public function getFeatures(): Features
    {
        return $this->features;
    }

    /**
     * How many items, for an offer that has a quantity_max.
     */
    public function getQuantity(): ?int
    {
        return $this->quantity;
    }

    /**
     * The payer's public key for this request, hex encoded. It signs the
     * request, and lets the payer prove later that it was the one who asked.
     */
    public function getPayerId(): string
    {
        return $this->payerId;
    }

    /**
     * A note from the payer. Like the offer's issuer, nothing vouches for it.
     */
    public function getPayerNote(): ?string
    {
        return $this->payerNote;
    }

    /**
     * Blinded paths to reach the payer, for a request without an offer.
     *
     * @return list<BlindedPath>
     */
    public function getPaths(): array
    {
        return $this->paths;
    }

    /**
     * The BIP 353 name ("user@domain", without the ₿) the payer resolved to
     * find the offer, if it used one.
     */
    public function getBip353Name(): ?string
    {
        return $this->bip353Name;
    }

    /**
     * The payer's BIP-340 signature, hex; null when this request is part of
     * an invoice.
     */
    public function getSignature(): ?string
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
     * @return InvoiceRequestArray
     */
    public function toArray(): array
    {
        return [
            'offer' => $this->offer->toArray(),
            'metadata' => $this->metadata,
            'chain' => $this->getChain(),
            'amount' => $this->amount,
            'features' => $this->features->getBits(),
            'quantity' => $this->quantity,
            'payer_id' => $this->payerId,
            'payer_note' => $this->payerNote,
            'paths' => array_map(static fn (BlindedPath $path): array => $path->toArray(), $this->paths),
            'bip_353_name' => $this->bip353Name,
            'signature' => $this->signature,
            'unknown_fields' => array_map(static fn (UnknownField $field): array => $field->toArray(), $this->unknownFields),
        ];
    }

    /**
     * @return InvoiceRequestArray
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
