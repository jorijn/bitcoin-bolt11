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
 * A BOLT #12 offer ("lno1..."): a reusable, long-lived payment code. A payer
 * asks the issuer for an invoice over the Lightning network and pays that.
 *
 * The same fields are copied into every invoice request and invoice made
 * from the offer, so InvoiceRequest::getOffer() and Invoice::getOffer()
 * return this class too. In an invoice request without an offer (a refund,
 * say) the payer fills a few of these fields itself.
 *
 * Binary values (keys, hashes, metadata) are lowercase hex.
 *
 * @see https://github.com/lightning/bolts/blob/master/12-offer-encoding.md#offers
 *
 * @phpstan-import-type BlindedPathArray from BlindedPath
 *
 * @phpstan-type OfferArray array{chains: list<string>, metadata: ?string, currency: ?string, amount: ?int, description: ?string, features: list<int>, absolute_expiry: ?string, paths: list<BlindedPathArray>, issuer: ?string, quantity_max: ?int, issuer_id: ?string, unknown_fields: list<array{type: int, value: string}>}
 */
final readonly class Offer implements \JsonSerializable
{
    /**
     * @param ?list<string>      $chains        chain hashes (hex), null when the field is absent
     * @param list<BlindedPath>  $paths
     * @param list<UnknownField> $unknownFields odd records in the offer ranges this library does not know
     */
    public function __construct(
        private ?array $chains,
        private ?string $metadata,
        private ?string $currency,
        private ?int $amount,
        private ?string $description,
        private Features $features,
        private ?int $absoluteExpiry,
        private array $paths,
        private ?string $issuer,
        private ?int $quantityMax,
        private ?string $issuerId,
        private array $unknownFields,
    ) {}

    /**
     * The chains the offer is for. Without an offer_chains field, that is
     * Bitcoin alone, so this never returns an empty list.
     *
     * @return list<string> chain hashes, hex; see Chain for the known ones
     */
    public function getChains(): array
    {
        return $this->chains ?? [Chain::BITCOIN];
    }

    /**
     * @param string $chainHash hex, for example Chain::BITCOIN
     */
    public function isForChain(string $chainHash): bool
    {
        return \in_array(strtolower($chainHash), $this->getChains(), true);
    }

    /**
     * Data the issuer put in the offer for its own use, hex encoded.
     */
    public function getMetadata(): ?string
    {
        return $this->metadata;
    }

    /**
     * The ISO 4217 code of the amount, or null when the amount is in
     * millisatoshis (or there is no amount).
     */
    public function getCurrency(): ?string
    {
        return $this->currency;
    }

    /**
     * The price per item: in millisatoshis without a currency, otherwise in
     * the currency's smallest unit (cents for USD). Null when the payer
     * chooses the amount, as for a donation.
     */
    public function getAmount(): ?int
    {
        return $this->amount;
    }

    /**
     * The amount when it is in millisatoshis, null when it is in another
     * currency or absent.
     */
    public function getMilliSatoshis(): ?int
    {
        return null === $this->currency ? $this->amount : null;
    }

    public function getDescription(): ?string
    {
        return $this->description;
    }

    public function getFeatures(): Features
    {
        return $this->features;
    }

    /**
     * When the issuer stops answering invoice requests for this offer, or
     * null if it does not expire.
     */
    public function getAbsoluteExpiry(): ?\DateTimeImmutable
    {
        return null === $this->absoluteExpiry
            ? null
            : (new \DateTimeImmutable('@0'))->setTimestamp($this->absoluteExpiry);
    }

    /**
     * A reader must not request an invoice for an expired offer. The decoder
     * does not reject expired offers, so they can still be shown; check here.
     */
    public function isExpired(?\DateTimeInterface $now = null): bool
    {
        return null !== $this->absoluteExpiry
            && ($now ?? new \DateTimeImmutable())->getTimestamp() > $this->absoluteExpiry;
    }

    /**
     * Blinded paths to reach the issuer. When present, invoice requests go
     * through one of them instead of to getIssuerId().
     *
     * @return list<BlindedPath>
     */
    public function getPaths(): array
    {
        return $this->paths;
    }

    /**
     * Who issued the offer, as text the issuer chose (often a domain name).
     * Nothing proves it: show it to the user, do not trust it.
     */
    public function getIssuer(): ?string
    {
        return $this->issuer;
    }

    /**
     * The most items one invoice can be for: null when the offer is for a
     * single item, 0 when there is no limit.
     */
    public function getQuantityMax(): ?int
    {
        return $this->quantityMax;
    }

    /**
     * The public key that signs invoices for this offer, hex encoded. Null
     * when the offer only has blinded paths; then each path's final blinded
     * node id signs instead.
     */
    public function getIssuerId(): ?string
    {
        return $this->issuerId;
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
     * @return OfferArray
     */
    public function toArray(): array
    {
        return [
            'chains' => $this->getChains(),
            'metadata' => $this->metadata,
            'currency' => $this->currency,
            'amount' => $this->amount,
            'description' => $this->description,
            'features' => $this->features->getBits(),
            'absolute_expiry' => $this->getAbsoluteExpiry()?->format(\DateTimeInterface::ATOM),
            'paths' => array_map(static fn (BlindedPath $path): array => $path->toArray(), $this->paths),
            'issuer' => $this->issuer,
            'quantity_max' => $this->quantityMax,
            'issuer_id' => $this->issuerId,
            'unknown_fields' => array_map(static fn (UnknownField $field): array => $field->toArray(), $this->unknownFields),
        ];
    }

    /**
     * @return OfferArray
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
