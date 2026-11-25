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
 * A verified BOLT #12 payer proof ("lnp1..."): evidence that the holder of
 * getPayerId() paid an invoice signed by getNodeId().
 *
 * Three things together make it a proof. The invoice signature shows the
 * node issued the invoice; the preimage shows the invoice was paid, as the
 * node only gives it out in exchange for the payment; and the proof
 * signature shows the proof comes from the payer that requested the
 * invoice, not from someone who merely saw the preimage.
 *
 * The payer chooses which invoice fields to show. The getters for optional
 * fields return null both when the invoice did not have the field and when
 * the payer left it out: the proof cannot tell the two apart.
 *
 * Binary values (keys, hashes) are lowercase hex.
 *
 * @see https://github.com/lightning/bolts/blob/master/12-offer-encoding.md#payer-proofs
 *
 * @phpstan-type PayerProofArray array{payer_id: string, node_id: string, payment_hash: string, preimage: string, invoice_signature: string, proof_signature: string, note: ?string, amount: ?int, created_at: ?string, description: ?string, issuer: ?string, issuer_id: ?string, payer_note: ?string, quantity: ?int, features: list<int>, disclosed_fields: array<int, string>, omitted_field_count: int, unknown_fields: list<array{type: int, value: string}>}
 */
final readonly class PayerProof implements \JsonSerializable
{
    /**
     * @param array<int, string> $disclosedFields every invoice field the proof shows, value hex by type
     * @param list<UnknownField> $unknownFields   odd records outside the invoice ranges this library does not know
     */
    public function __construct(
        private string $payerId,
        private string $nodeId,
        private string $paymentHash,
        private string $preimage,
        private string $invoiceSignature,
        private string $proofSignature,
        private ?string $note,
        private ?int $amount,
        private ?int $createdAt,
        private ?string $description,
        private ?string $issuer,
        private ?string $issuerId,
        private ?string $payerNote,
        private ?int $quantity,
        private Features $features,
        private array $disclosedFields,
        private int $omittedFieldCount,
        private array $unknownFields,
    ) {}

    /**
     * The key the payer requested the invoice with (invreq_payer_id). The
     * proof signature is made with it.
     */
    public function getPayerId(): string
    {
        return $this->payerId;
    }

    /**
     * The key that signed the invoice (invoice_node_id). Check that it is the
     * node you expect, such as your own: the proof only shows that this key
     * was paid, and anyone can run a node.
     */
    public function getNodeId(): string
    {
        return $this->nodeId;
    }

    public function getPaymentHash(): string
    {
        return $this->paymentHash;
    }

    /**
     * The payment preimage: SHA-256 of it is getPaymentHash().
     */
    public function getPreimage(): string
    {
        return $this->preimage;
    }

    /**
     * The node's BIP-340 signature over the whole invoice, hex.
     */
    public function getInvoiceSignature(): string
    {
        return $this->invoiceSignature;
    }

    /**
     * The payer's BIP-340 signature over this proof, hex.
     */
    public function getProofSignature(): string
    {
        return $this->proofSignature;
    }

    /**
     * Text the payer added to the proof (proof_note), covered by the proof
     * signature. Ask for a note of your choosing to be sure a proof was made
     * for you and not copied from elsewhere.
     */
    public function getNote(): ?string
    {
        return $this->note;
    }

    /**
     * The amount paid in millisatoshis (invoice_amount), if shown.
     */
    public function getAmount(): ?int
    {
        return $this->amount;
    }

    /**
     * When the invoice was created (invoice_created_at), if shown.
     */
    public function getCreatedAt(): ?\DateTimeImmutable
    {
        return null === $this->createdAt ? null : (new \DateTimeImmutable('@0'))->setTimestamp($this->createdAt);
    }

    /**
     * What the offer was for (offer_description), if shown. It comes from the
     * offer's issuer: escape it before putting it in HTML.
     */
    public function getDescription(): ?string
    {
        return $this->description;
    }

    /**
     * Who made the offer (offer_issuer), if shown. Escape it before display.
     */
    public function getIssuer(): ?string
    {
        return $this->issuer;
    }

    /**
     * The offer's issuer key (offer_issuer_id), if shown. The decoder checks
     * that it matches getNodeId().
     */
    public function getIssuerId(): ?string
    {
        return $this->issuerId;
    }

    /**
     * The payer's note to the issuer (invreq_payer_note), if shown. Not to be
     * confused with getNote(), which is added to the proof afterwards.
     */
    public function getPayerNote(): ?string
    {
        return $this->payerNote;
    }

    /**
     * How many items were bought (invreq_quantity), if shown.
     */
    public function getQuantity(): ?int
    {
        return $this->quantity;
    }

    /**
     * The invoice features. A writer must show these whenever the invoice
     * had them, so empty means the invoice had none.
     */
    public function getFeatures(): Features
    {
        return $this->features;
    }

    /**
     * Every invoice field the proof shows, including the ones with their own
     * getter: the raw value as hex, by TLV type.
     *
     * @return array<int, string>
     */
    public function getDisclosedFields(): array
    {
        return $this->disclosedFields;
    }

    /**
     * How many invoice fields the payer left out, invreq_metadata included
     * (it is always left out). The invoice signature is not counted.
     */
    public function getOmittedFieldCount(): int
    {
        return $this->omittedFieldCount;
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
     * @return PayerProofArray
     */
    public function toArray(): array
    {
        return [
            'payer_id' => $this->payerId,
            'node_id' => $this->nodeId,
            'payment_hash' => $this->paymentHash,
            'preimage' => $this->preimage,
            'invoice_signature' => $this->invoiceSignature,
            'proof_signature' => $this->proofSignature,
            'note' => $this->note,
            'amount' => $this->amount,
            'created_at' => $this->getCreatedAt()?->format(\DateTimeInterface::ATOM),
            'description' => $this->description,
            'issuer' => $this->issuer,
            'issuer_id' => $this->issuerId,
            'payer_note' => $this->payerNote,
            'quantity' => $this->quantity,
            'features' => $this->features->getBits(),
            'disclosed_fields' => $this->disclosedFields,
            'omitted_field_count' => $this->omittedFieldCount,
            'unknown_fields' => array_map(static fn (UnknownField $field): array => $field->toArray(), $this->unknownFields),
        ];
    }

    /**
     * @return PayerProofArray
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
