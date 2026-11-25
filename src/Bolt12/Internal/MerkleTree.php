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
            $level[] = self::branch(
                Secp256k1::taggedHash('LnLeaf', $record->raw),
                Secp256k1::taggedHash($nonceTag, $record->rawType),
            );
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
     * The 32 bytes a signature field signs: H("lightning" || message name ||
     * field name, merkle root). The tag stops a signature over one kind of
     * message from passing as another.
     *
     * @param string $messageName "invoice_request" or "invoice"
     * @param string $fieldName   "signature"
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
     * Inner nodes hash the smaller child first, so a proof never has to say
     * whether a sibling sits on the left or the right.
     */
    private static function branch(string $first, string $second): string
    {
        return Secp256k1::taggedHash('LnBranch', strcmp($first, $second) < 0 ? $first.$second : $second.$first);
    }
}
