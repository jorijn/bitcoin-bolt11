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

namespace Jorijn\Bitcoin\Bolt12\Internal;

use Jorijn\Bitcoin\Bolt11\Internal\Secp256k1;

/**
 * The merkle root that BOLT #12 signatures sign.
 *
 * Signing a merkle root instead of the whole message means a payer can later
 * reveal some fields of an invoice and prove the rest was signed too, without
 * showing it. Each field leaf is paired with a nonce leaf derived from the
 * first record, so a hidden field cannot be guessed from its hash.
 *
 * @internal not covered by the backward compatibility promise
 *
 * @see https://github.com/lightning/bolts/blob/master/12-offer-encoding.md#signature-calculation
 */
final class MerkleTree
{
    /** Signature records (types 240 to 1000) are not part of what is signed. */
    public const SIGNATURE_TYPE_MIN = 240;
    public const SIGNATURE_TYPE_MAX = 1000;

    /**
     * @param list<TlvRecord> $records the whole stream, in order; signature records are skipped
     *
     * @return string 32 bytes
     *
     * @throws \InvalidArgumentException when there is nothing to sign
     */
    public static function root(array $records): string
    {
        $records = array_values(array_filter($records, static fn (TlvRecord $record): bool => !self::isSignatureType($record->type)));
        if ([] === $records) {
            throw new \InvalidArgumentException('there are no records to sign');
        }

        // The nonce tag includes the numerically first record. In invoice
        // requests and invoices that is invreq_metadata, which the payer fills
        // with random bytes, so nobody else can compute the nonce leaves.
        $nonceTag = 'LnNonce'.$records[0]->raw;

        $level = [];
        foreach ($records as $record) {
            $level[] = self::leaf($record->raw, Secp256k1::taggedHash($nonceTag, $record->rawType));
        }

        // Pair neighbours and carry an odd one up unchanged, level by level.
        // With a number of leaves that is not a power of two this makes the
        // tree deepest on the left, as the specification describes.
        while (\count($level) > 1) {
            $next = [];
            for ($i = 0, $count = \count($level); $i < $count; $i += 2) {
                $next[] = isset($level[$i + 1]) ? self::branch($level[$i], $level[$i + 1]) : $level[$i];
            }

            $level = $next;
        }

        return $level[0];
    }

    /**
     * Computes the root of a tree of which some leaves are hidden, as a payer
     * proof does: it shows some invoice fields and hides the rest, and gives
     * just enough hashes to rebuild the root the invoice signature signed.
     *
     * The shape matches root(): for n leaves the left subtree holds the
     * largest power of two below n (deepest on the left). Walking it depth
     * first, left before right, each node with exactly one hidden side takes
     * the next missing hash for that side: the order a writer must use.
     *
     * @param list<?string> $leaves        in field order: leaf() of a shown field, null for a hidden one
     * @param list<string>  $missingHashes the 32-byte hashes of the hidden subtrees, in that order
     *
     * @return string 32 bytes
     *
     * @throws \InvalidArgumentException when the missing hashes are too few or too many, or nothing is shown
     *
     * @see https://github.com/lightning/bolts/blob/master/12-offer-encoding.md#payer-proofs
     */
    public static function reconstructRoot(array $leaves, array $missingHashes): string
    {
        if ([] === $leaves) {
            throw new \InvalidArgumentException('there are no leaves');
        }

        $next = 0;
        $root = self::subtree($leaves, 0, \count($leaves), $missingHashes, $next);

        // A tree with every leaf hidden proves nothing, and has nothing the
        // missing hashes could attach to.
        if (null === $root) {
            throw new \InvalidArgumentException('every leaf is hidden');
        }

        if ($next !== \count($missingHashes)) {
            throw new \InvalidArgumentException(\sprintf('%d missing hashes given, %d used', \count($missingHashes), $next));
        }

        return $root;
    }

    /**
     * A leaf as the tree hashes it: the field paired with its nonce.
     *
     * @param string $raw   the whole record as encoded
     * @param string $nonce H("LnNonce" || first record, type), 32 bytes
     */
    public static function leaf(string $raw, string $nonce): string
    {
        return self::branch(Secp256k1::taggedHash('LnLeaf', $raw), $nonce);
    }

    /**
     * The 32 bytes a signature field signs: H("lightning" || message name ||
     * field name, merkle root). The tag stops a signature over one kind of
     * message from passing as another.
     *
     * @param string $messageName "invoice_request", "invoice" or "payer_proof"
     * @param string $fieldName   "signature", or "proof_signature" in a payer proof
     */
    public static function signatureHash(string $messageName, string $fieldName, string $merkleRoot): string
    {
        return Secp256k1::taggedHash('lightning'.$messageName.$fieldName, $merkleRoot);
    }

    public static function isSignatureType(int $type): bool
    {
        return $type >= self::SIGNATURE_TYPE_MIN && $type <= self::SIGNATURE_TYPE_MAX;
    }

    /**
     * @param list<?string> $leaves
     * @param list<string>  $missingHashes
     *
     * @return null|string null when the whole subtree is hidden
     */
    private static function subtree(array $leaves, int $offset, int $count, array $missingHashes, int &$next): ?string
    {
        if (1 === $count) {
            return $leaves[$offset];
        }

        $leftCount = 1;
        while ($leftCount * 2 < $count) {
            $leftCount *= 2;
        }

        $left = self::subtree($leaves, $offset, $leftCount, $missingHashes, $next);
        $right = self::subtree($leaves, $offset + $leftCount, $count - $leftCount, $missingHashes, $next);

        // A hidden subtree next to another hidden one stays hidden: its hash
        // comes in one piece from higher up, which keeps the proof small.
        if (null === $left && null === $right) {
            return null;
        }

        $left ??= self::takeMissingHash($missingHashes, $next);
        $right ??= self::takeMissingHash($missingHashes, $next);

        return self::branch($left, $right);
    }

    /**
     * @param list<string> $missingHashes
     */
    private static function takeMissingHash(array $missingHashes, int &$next): string
    {
        if (!isset($missingHashes[$next])) {
            throw new \InvalidArgumentException('too few missing hashes to rebuild the tree');
        }

        return $missingHashes[$next++];
    }

    /**
     * Inner nodes hash the smaller child first, so a proof never has to say
     * whether a sibling sits on the left or the right.
     */
    private static function branch(string $first, string $second): string
    {
        return Secp256k1::taggedHash('LnBranch', strcmp($first, $second) < 0 ? $first.$second : $second.$first);
    }
}
