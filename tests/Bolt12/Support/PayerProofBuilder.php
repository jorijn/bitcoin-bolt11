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

namespace Tests\Jorijn\Bitcoin\Bolt12\Support;

use Jorijn\Bitcoin\Bolt11\Internal\Secp256k1;
use Jorijn\Bitcoin\Bolt12\Internal\MerkleTree;
use Jorijn\Bitcoin\Bolt12\Internal\TlvRecord;

/**
 * Writes payer proofs for tests, following the writer requirements of
 * BOLT #12 step by step, so each reader rule can be tested with a proof that
 * is valid except for the one thing under test. Changes made with with() or
 * without() are applied before the payer signs, so only the rule under test
 * fails, not the proof signature.
 */
final class PayerProofBuilder
{
    /** The preimage of the vectors (0x01 repeated). */
    public const PREIMAGE = '0101010101010101010101010101010101010101010101010101010101010101';

    /** Fields a writer must always include, as far as the invoice has them. */
    private const REQUIRED_TYPES = [88, 168, 174, 176];

    /** @var list<int> */
    private array $included = [];

    private ?string $note = null;

    /** Writes proof_omitted_tlvs even when empty, which the specification allows. */
    private bool $explicitEmptyMarkers = false;

    /** @var array<int, string> */
    private array $overrides = [];

    /** @var list<int> */
    private array $removed = [];

    private function __construct(
        private readonly string $invoiceBytes,
        private readonly string $preimage,
    ) {}

    /**
     * A proof for an invoice built with Bolt12Builder. The invoice gets the
     * payment hash of the preimage and is signed by the issuer key here.
     */
    public static function forInvoice(?Bolt12Builder $invoice = null, string $preimage = self::PREIMAGE, string $nodeSecret = Bolt12Builder::ISSUER_SECRET): self
    {
        $signed = ($invoice ?? Bolt12Builder::invoice())
            ->with(168, hash('sha256', (string) hex2bin($preimage), true))
            ->sign('invoice', $nodeSecret)
        ;

        return new self($signed->bytes(), $preimage);
    }

    /**
     * A proof for an already signed invoice, as the specification's vectors
     * give it.
     */
    public static function forInvoiceBytes(string $invoiceBytes, string $preimage): self
    {
        return new self($invoiceBytes, $preimage);
    }

    /**
     * Also shows these invoice fields.
     */
    public function including(int ...$types): self
    {
        $clone = clone $this;
        $clone->included = [...$clone->included, ...array_values($types)];

        return $clone;
    }

    /**
     * Shows every invoice field but invreq_metadata.
     */
    public function includingAll(): self
    {
        $types = array_map(static fn (TlvRecord $record): int => $record->type, TlvRecord::parseStream($this->invoiceBytes));

        return $this->including(...array_values(array_filter($types, static fn (int $type): bool => 0 !== $type && !MerkleTree::isSignatureType($type))));
    }

    public function withNote(string $note): self
    {
        $clone = clone $this;
        $clone->note = $note;

        return $clone;
    }

    public function withExplicitEmptyMarkers(): self
    {
        $clone = clone $this;
        $clone->explicitEmptyMarkers = true;

        return $clone;
    }

    /**
     * Sets or replaces a record of the proof, before the payer signs.
     */
    public function with(int $type, string $value): self
    {
        $clone = clone $this;
        $clone->overrides[$type] = $value;

        return $clone;
    }

    /**
     * Leaves a record out of the proof, before the payer signs.
     */
    public function without(int $type): self
    {
        $clone = clone $this;
        $clone->removed[] = $type;

        return $clone;
    }

    /**
     * The proof, signed by the payer key unless $payerSecret is null.
     */
    public function build(?string $payerSecret = Bolt12Builder::PAYER_SECRET): Bolt12Builder
    {
        $proof = Bolt12Builder::create();
        foreach ($this->proofRecords() as $type => $value) {
            if (!\in_array($type, $this->removed, true)) {
                $proof = $proof->with($type, $value);
            }
        }

        foreach ($this->overrides as $type => $value) {
            $proof = $proof->with($type, $value);
        }

        if (null === $payerSecret) {
            return $proof;
        }

        $root = MerkleTree::root(TlvRecord::parseStream($proof->without(241)->bytes()));
        $hash = MerkleTree::signatureHash('payer_proof', 'proof_signature', $root);

        return $proof->with(241, Bolt12Builder::schnorrSign($hash, $payerSecret, str_repeat("\0", 32)));
    }

    public function encode(): string
    {
        return $this->build()->encode('lnp');
    }

    /**
     * The records a writer puts in the proof, by type.
     *
     * @return array<int, string>
     */
    public function proofRecords(): array
    {
        $records = TlvRecord::parseStream($this->invoiceBytes);
        $nonceTag = 'LnNonce'.$records[0]->raw;

        $proof = [];
        $leafHashes = '';
        $markers = '';
        $explicitEmptyMarkers = $this->explicitEmptyMarkers;
        // The number of the field before, shown or omitted: markers follow on from it.
        $previous = 0;
        $shown = [];

        foreach ($records as $record) {
            if (240 === $record->type) {
                $proof[240] = $record->value;
            }

            if (MerkleTree::isSignatureType($record->type)) {
                continue;
            }

            $isShown = 0 !== $record->type
                && (\in_array($record->type, self::REQUIRED_TYPES, true) || \in_array($record->type, $this->included, true));
            $shown[] = $isShown;

            if ($isShown) {
                $proof[$record->type] = $record->value;
                $leafHashes .= Secp256k1::taggedHash($nonceTag, $record->rawType);
                $previous = $record->type;
            } elseif (0 !== $record->type) {
                // After 239 the numbering skips the signature range.
                $previous = $previous >= 239 && $previous < 1_000_000_000 ? 1_000_000_000 : $previous + 1;
                $markers .= Bolt12Builder::bigSize($previous);
            }
        }

        $proof[1001] = (string) hex2bin($this->preimage);
        if ('' !== $markers || $explicitEmptyMarkers) {
            $proof[1002] = $markers;
        }

        $proof[1003] = $this->missingHashes($records, $nonceTag, $shown);
        $proof[1004] = $leafHashes;
        if (null !== $this->note) {
            $proof[1005] = $this->note;
        }

        ksort($proof);

        return $proof;
    }

    /**
     * The hashes of the omitted branches, depth first from left to right:
     * each node with exactly one side omitted contributes that side's hash.
     *
     * @param list<TlvRecord> $records
     * @param list<bool>      $shown   per non-signature record
     */
    private function missingHashes(array $records, string $nonceTag, array $shown): string
    {
        $leaves = [];
        foreach (array_values(array_filter($records, static fn (TlvRecord $record): bool => !MerkleTree::isSignatureType($record->type))) as $record) {
            $leaves[] = MerkleTree::leaf($record->raw, Secp256k1::taggedHash($nonceTag, $record->rawType));
        }

        $missing = '';
        $this->walk($leaves, $shown, 0, \count($leaves), $missing);

        return $missing;
    }

    /**
     * @param list<string> $leaves
     * @param list<bool>   $shown
     *
     * @return array{string, bool} the subtree's hash, and whether it is entirely omitted
     */
    private function walk(array $leaves, array $shown, int $offset, int $count, string &$missing): array
    {
        if (1 === $count) {
            return [$leaves[$offset], !$shown[$offset]];
        }

        $leftCount = 1;
        while ($leftCount * 2 < $count) {
            $leftCount *= 2;
        }

        [$left, $leftOmitted] = $this->walk($leaves, $shown, $offset, $leftCount, $missing);
        [$right, $rightOmitted] = $this->walk($leaves, $shown, $offset + $leftCount, $count - $leftCount, $missing);

        if ($leftOmitted !== $rightOmitted) {
            $missing .= $leftOmitted ? $left : $right;
        }

        $hash = Secp256k1::taggedHash('LnBranch', strcmp($left, $right) < 0 ? $left.$right : $right.$left);

        return [$hash, $leftOmitted && $rightOmitted];
    }
}
