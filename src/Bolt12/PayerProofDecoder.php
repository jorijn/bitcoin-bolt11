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

namespace Jorijn\Bitcoin\Bolt12;

use Jorijn\Bitcoin\Bolt11\Internal\Secp256k1;
use Jorijn\Bitcoin\Bolt12\Exception\Bolt12DecodeException;
use Jorijn\Bitcoin\Bolt12\Exception\InvalidEncodingException;
use Jorijn\Bitcoin\Bolt12\Exception\InvalidFieldException;
use Jorijn\Bitcoin\Bolt12\Exception\InvalidSignatureException;
use Jorijn\Bitcoin\Bolt12\Exception\MalformedTlvException;
use Jorijn\Bitcoin\Bolt12\Exception\UnknownRequiredFieldException;
use Jorijn\Bitcoin\Bolt12\Internal\Bolt12String;
use Jorijn\Bitcoin\Bolt12\Internal\ByteReader;
use Jorijn\Bitcoin\Bolt12\Internal\FieldReader;
use Jorijn\Bitcoin\Bolt12\Internal\MerkleTree;
use Jorijn\Bitcoin\Bolt12\Internal\TlvRecord;
use Jorijn\Bitcoin\Bolt12\Model\PayerProof;
use Jorijn\Bitcoin\Bolt12\Model\UnknownField;

/**
 * Decodes BOLT #12 payer proofs and verifies them: the invoice signature
 * over the fields the payer shows, the preimage against the payment hash,
 * and the payer's own signature over the proof.
 *
 * Verifying says the holder of the payer key paid an invoice that the node
 * key signed. Whether that node is the one you care about is for the caller
 * to check (PayerProof::getNodeId()), as is whether the proof was made for
 * you: ask the payer for a note of your choosing (PayerProof::getNote()).
 *
 * Making payer proofs is out of scope: that takes the payer's secret key and
 * the invoice, which a wallet holds.
 *
 * @see https://github.com/lightning/bolts/blob/master/12-offer-encoding.md#payer-proofs
 */
final class PayerProofDecoder implements PayerProofDecoderInterface
{
    public const PREFIX = 'lnp';

    private const INVREQ_METADATA = 0;
    private const OFFER_DESCRIPTION = 10;
    private const OFFER_ISSUER = 18;
    private const OFFER_ISSUER_ID = 22;
    private const INVREQ_AMOUNT = 82;
    private const INVREQ_QUANTITY = 86;
    private const INVREQ_PAYER_ID = 88;
    private const INVREQ_PAYER_NOTE = 89;
    private const INVOICE_CREATED_AT = 164;
    private const INVOICE_PAYMENT_HASH = 168;
    private const INVOICE_AMOUNT = 170;
    private const INVOICE_FEATURES = 174;
    private const INVOICE_NODE_ID = 176;

    private const SIGNATURE = 240;
    private const PROOF_SIGNATURE = 241;
    private const PROOF_PREIMAGE = 1001;
    private const PROOF_OMITTED_TLVS = 1002;
    private const PROOF_MISSING_HASHES = 1003;
    private const PROOF_LEAF_HASHES = 1004;
    private const PROOF_NOTE = 1005;

    /**
     * The invoice fields a payer_proof may carry, from the specification's
     * table: the offer, invoice request and invoice fields, without
     * invreq_metadata. An unknown even type outside this list is an error.
     */
    private const INVOICE_TYPES = [
        2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22,
        80, 82, 84, 86, 88, 89, 90, 91,
        160, 162, 164, 166, 168, 170, 172, 174, 176,
    ];

    private const PROOF_TYPES = [
        self::SIGNATURE, self::PROOF_SIGNATURE, self::PROOF_PREIMAGE, self::PROOF_OMITTED_TLVS,
        self::PROOF_MISSING_HASHES, self::PROOF_LEAF_HASHES, self::PROOF_NOTE,
    ];

    /** Fields every payer proof must have: without any of them, it proves nothing. */
    private const REQUIRED_TYPES = [
        self::INVREQ_PAYER_ID, self::INVOICE_PAYMENT_HASH, self::INVOICE_NODE_ID, self::SIGNATURE,
        self::PROOF_PREIMAGE, self::PROOF_MISSING_HASHES, self::PROOF_LEAF_HASHES, self::PROOF_SIGNATURE,
    ];

    /**
     * The TLV ranges of an invoice outside the signature range: the fields
     * the invoice signature's merkle tree covers, and the only numbers an
     * omitted field may be given.
     */
    private const INVOICE_RANGES = [[1, 239], [1_000_000_000, 3_999_999_999]];

    public function decode(string $payerProof): PayerProof
    {
        try {
            return $this->decodeProof($payerProof);
        } catch (Bolt12DecodeException $exception) {
            throw $exception;
        } catch (\Throwable $exception) {
            // Safety net, as in the other decoders: callers rely on catching
            // Bolt12DecodeException alone.
            throw new MalformedTlvException('unable to decode payer proof: '.$exception->getMessage(), 0, $exception);
        }
    }

    private function decodeProof(string $string): PayerProof
    {
        $records = $this->parseString($string);
        [$fields, $disclosed, $unknown] = $this->index($records);

        foreach (self::REQUIRED_TYPES as $type) {
            if (!isset($fields[$type])) {
                throw new InvalidFieldException(\sprintf('payer proof has no %s', $this->fieldName($type)));
            }
        }

        $payerId = FieldReader::point($fields[self::INVREQ_PAYER_ID], 'invreq_payer_id');
        $nodeId = FieldReader::point($fields[self::INVOICE_NODE_ID], 'invoice_node_id');
        $paymentHash = FieldReader::fixed($fields[self::INVOICE_PAYMENT_HASH], 32, 'invoice_payment_hash');
        $preimage = FieldReader::fixed($fields[self::PROOF_PREIMAGE], 32, 'proof_preimage');

        // The node hands out the preimage only for the payment, so holding it
        // is what shows the invoice was paid.
        if (hash('sha256', (string) hex2bin($preimage)) !== $paymentHash) {
            throw new InvalidFieldException('proof_preimage does not hash to invoice_payment_hash');
        }

        $invoiceSignature = FieldReader::signature($fields[self::SIGNATURE]);
        $markers = $this->markers($fields[self::PROOF_OMITTED_TLVS] ?? null, $disclosed);
        $invoiceRoot = $this->invoiceMerkleRoot($fields, $disclosed, $markers);
        $this->verify('invoice', 'signature', $invoiceRoot, $invoiceSignature, $nodeId);

        // The proof signature covers every record of the proof outside the
        // signature range: the shown fields and the proof fields alike, so
        // nobody can change the note or swap the hashes without the payer key.
        $proofSignature = FieldReader::signature($fields[self::PROOF_SIGNATURE], 'proof_signature');
        $this->verify('payer_proof', 'proof_signature', MerkleTree::root($records), $proofSignature, $payerId);

        return $this->buildProof($fields, $disclosed, $unknown, \count($markers), $payerId, $nodeId, $paymentHash, $preimage, $invoiceSignature, $proofSignature);
    }

    /**
     * @return list<TlvRecord>
     */
    private function parseString(string $string): array
    {
        try {
            [$prefix, $bytes] = Bolt12String::decode($string);
        } catch (\InvalidArgumentException $exception) {
            throw new InvalidEncodingException($exception->getMessage(), 0, $exception);
        }

        if (self::PREFIX !== $prefix) {
            throw new InvalidEncodingException(\sprintf('expected prefix "%s", got "%s"', self::PREFIX, $prefix));
        }

        try {
            $records = TlvRecord::parseStream($bytes);
        } catch (\InvalidArgumentException $exception) {
            throw new MalformedTlvException($exception->getMessage(), 0, $exception);
        }

        if ([] === $records) {
            throw new MalformedTlvException('message is empty');
        }

        return $records;
    }

    /**
     * Sorts the records into known fields, shown invoice fields (in order)
     * and unknown odd proof fields.
     *
     * @param list<TlvRecord> $records
     *
     * @return array{array<int, TlvRecord>, list<TlvRecord>, list<UnknownField>}
     */
    private function index(array $records): array
    {
        $fields = [];
        $disclosed = [];
        $unknown = [];

        foreach ($records as $record) {
            // invreq_metadata is the secret the nonces derive from: with it,
            // anyone could guess the hidden fields from their hashes.
            if (self::INVREQ_METADATA === $record->type) {
                throw new InvalidFieldException('payer proof must not include invreq_metadata');
            }

            $isKnown = \in_array($record->type, self::INVOICE_TYPES, true) || \in_array($record->type, self::PROOF_TYPES, true);
            if (!$isKnown && 0 === $record->type % 2) {
                throw new UnknownRequiredFieldException(\sprintf('unknown even TLV type %d', $record->type), $record->type);
            }

            if ($this->isInvoiceType($record->type)) {
                // Unknown odd invoice fields are still part of the signed
                // invoice, so they take part in the tree like any other.
                $disclosed[] = $record;
                $fields[$record->type] = $record;
            } elseif ($isKnown) {
                $fields[$record->type] = $record;
            } else {
                $unknown[] = new UnknownField($record->type, bin2hex($record->value));
            }
        }

        return [$fields, $disclosed, $unknown];
    }

    /**
     * Rebuilds the merkle root the invoice signature signed, from the shown
     * fields, the numbers that stand in for the omitted ones, and the hashes
     * of the omitted subtrees.
     *
     * @param array<int, TlvRecord> $fields
     * @param list<TlvRecord>       $disclosed
     * @param list<int>             $markers   from markers()
     *
     * @return string 32 bytes
     */
    private function invoiceMerkleRoot(array $fields, array $disclosed, array $markers): string
    {
        // A nonce needs invreq_metadata, which the proof leaves out, so the
        // writer supplies one nonce hash per shown field.
        $nonces = $this->hashes($fields[self::PROOF_LEAF_HASHES], 'proof_leaf_hashes');
        if (\count($nonces) !== \count($disclosed)) {
            throw new InvalidFieldException(\sprintf('proof_leaf_hashes has %d hashes for %d shown invoice fields', \count($nonces), \count($disclosed)));
        }

        // Each field takes its place in the tree by number: shown fields by
        // their type, omitted ones by their marker. invreq_metadata is always
        // omitted, and its marker, 0, is implied.
        $leaves = [0 => null];
        foreach ($markers as $marker) {
            $leaves[$marker] = null;
        }

        foreach ($disclosed as $i => $record) {
            $leaves[$record->type] = MerkleTree::leaf($record->raw, $nonces[$i]);
        }

        ksort($leaves);

        try {
            return MerkleTree::reconstructRoot(array_values($leaves), $this->hashes($fields[self::PROOF_MISSING_HASHES], 'proof_missing_hashes'));
        } catch (\InvalidArgumentException $exception) {
            throw new InvalidFieldException('proof_missing_hashes does not fit the omitted fields: '.$exception->getMessage(), 0, $exception);
        }
    }

    /**
     * Reads proof_omitted_tlvs and checks the numbers are the ones a writer
     * must choose. They hide the real types of the omitted fields but keep
     * their order: each is one past the field before it, whether that field
     * is shown or omitted, and after 239 the numbering jumps to 1000000000,
     * past the signature range.
     *
     * The specification's reader rule spells the jump out only after an
     * omitted field. After a shown field 239 its writer rule would give 240,
     * which the reader must reject; like Core Lightning, this reader expects
     * the jump there too.
     *
     * @param list<TlvRecord> $disclosed
     *
     * @return list<int>
     */
    private function markers(?TlvRecord $record, array $disclosed): array
    {
        if (null === $record) {
            return [];
        }

        $reader = new ByteReader($record->value);
        $markers = [];

        try {
            while (!$reader->isAtEnd()) {
                $markers[] = $reader->readBigSize();
            }
        } catch (\InvalidArgumentException $exception) {
            throw new MalformedTlvException('proof_omitted_tlvs is malformed: '.$exception->getMessage(), 0, $exception);
        }

        $shownTypes = array_map(static fn (TlvRecord $field): int => $field->type, $disclosed);
        $previous = 0;
        foreach ($markers as $marker) {
            if (0 === $marker) {
                throw new InvalidFieldException('proof_omitted_tlvs contains 0, which is always implied');
            }

            if (!$this->isInvoiceType($marker)) {
                throw new InvalidFieldException(\sprintf('proof_omitted_tlvs contains %d, outside the invoice ranges', $marker));
            }

            if ($marker <= $previous) {
                throw new InvalidFieldException('proof_omitted_tlvs is not in strictly ascending order');
            }

            if (\in_array($marker, $shownTypes, true)) {
                throw new InvalidFieldException(\sprintf('proof_omitted_tlvs contains %d, the type of a shown field', $marker));
            }

            $previous = $marker;
        }

        // Walk all fields in order, with the implied 0 first: every marker
        // must follow directly from the number before it.
        $sequence = [0 => true];
        foreach ($markers as $marker) {
            $sequence[$marker] = true;
        }

        foreach ($shownTypes as $type) {
            $sequence[$type] = false;
        }

        ksort($sequence);
        $before = null;
        foreach ($sequence as $number => $isMarker) {
            if ($isMarker && null !== $before && $number !== $this->nextMarker($before)) {
                throw new InvalidFieldException(\sprintf('proof_omitted_tlvs contains %d where %d was due', $number, $this->nextMarker($before)));
            }

            $before = $number;
        }

        return $markers;
    }

    private function nextMarker(int $previous): int
    {
        return $previous >= 239 && $previous < 1_000_000_000 ? 1_000_000_000 : $previous + 1;
    }

    private function isInvoiceType(int $type): bool
    {
        foreach (self::INVOICE_RANGES as [$min, $max]) {
            if ($type >= $min && $type <= $max) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return list<string> 32-byte hashes
     */
    private function hashes(TlvRecord $record, string $name): array
    {
        if (0 !== \strlen($record->value) % 32) {
            throw new MalformedTlvException(\sprintf('%s is not a list of 32-byte hashes', $name));
        }

        return '' === $record->value ? [] : str_split($record->value, 32);
    }

    private function verify(string $messageName, string $fieldName, string $merkleRoot, string $signature, string $publicKey): void
    {
        $hash = MerkleTree::signatureHash($messageName, $fieldName, $merkleRoot);

        if (!Secp256k1::verifySchnorr($hash, (string) hex2bin($signature), (string) hex2bin($publicKey))) {
            throw new InvalidSignatureException(\sprintf('%s is not valid', 'signature' === $fieldName ? 'invoice signature' : $fieldName));
        }
    }

    /**
     * @param array<int, TlvRecord> $fields
     * @param list<TlvRecord>       $disclosed
     * @param list<UnknownField>    $unknown
     */
    private function buildProof(array $fields, array $disclosed, array $unknown, int $markerCount, string $payerId, string $nodeId, string $paymentHash, string $preimage, string $invoiceSignature, string $proofSignature): PayerProof
    {
        $issuerId = isset($fields[self::OFFER_ISSUER_ID]) ? FieldReader::point($fields[self::OFFER_ISSUER_ID], 'offer_issuer_id') : null;

        // A reader of the invoice would have refused these two, so a proof
        // that shows them proves payment of an invoice nobody should have
        // paid. Worse, with the issuer id a payer could pay a node of its own
        // and "prove" it paid someone else's offer.
        if (null !== $issuerId && $issuerId !== $nodeId) {
            throw new InvalidFieldException('invoice_node_id is not the offer_issuer_id');
        }

        $amount = isset($fields[self::INVOICE_AMOUNT]) ? FieldReader::truncated($fields[self::INVOICE_AMOUNT], 8, 'invoice_amount') : null;
        if (null !== $amount && isset($fields[self::INVREQ_AMOUNT]) && $amount !== FieldReader::truncated($fields[self::INVREQ_AMOUNT], 8, 'invreq_amount')) {
            throw new InvalidFieldException('invoice_amount differs from invreq_amount');
        }

        $disclosedFields = [];
        foreach ($disclosed as $record) {
            $disclosedFields[$record->type] = bin2hex($record->value);
        }

        return new PayerProof(
            $payerId,
            $nodeId,
            $paymentHash,
            $preimage,
            $invoiceSignature,
            $proofSignature,
            FieldReader::text($fields[self::PROOF_NOTE] ?? null, 'proof_note'),
            $amount,
            isset($fields[self::INVOICE_CREATED_AT]) ? FieldReader::timestamp($fields[self::INVOICE_CREATED_AT], 'invoice_created_at') : null,
            FieldReader::text($fields[self::OFFER_DESCRIPTION] ?? null, 'offer_description'),
            FieldReader::text($fields[self::OFFER_ISSUER] ?? null, 'offer_issuer'),
            $issuerId,
            FieldReader::text($fields[self::INVREQ_PAYER_NOTE] ?? null, 'invreq_payer_note'),
            isset($fields[self::INVREQ_QUANTITY]) ? FieldReader::truncated($fields[self::INVREQ_QUANTITY], 8, 'invreq_quantity') : null,
            // Reported, not enforced: the payer already paid, so a feature
            // this library does not know does not make the proof less true.
            FieldReader::features($fields[self::INVOICE_FEATURES] ?? null, 'invoice_features', null),
            $disclosedFields,
            // invreq_metadata is omitted without a marker.
            1 + $markerCount,
            $unknown,
        );
    }

    private function fieldName(int $type): string
    {
        return match ($type) {
            self::INVREQ_PAYER_ID => 'invreq_payer_id',
            self::INVOICE_PAYMENT_HASH => 'invoice_payment_hash',
            self::INVOICE_NODE_ID => 'invoice_node_id',
            self::SIGNATURE => 'signature',
            self::PROOF_SIGNATURE => 'proof_signature',
            self::PROOF_PREIMAGE => 'proof_preimage',
            self::PROOF_MISSING_HASHES => 'proof_missing_hashes',
            self::PROOF_LEAF_HASHES => 'proof_leaf_hashes',
            default => 'type '.$type,
        };
    }
}
