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

/**
 * One type-length-value record of a TLV stream.
 *
 * @internal not covered by the backward compatibility promise
 */
final readonly class TlvRecord
{
    /**
     * @param int    $type    the record type
     * @param string $value   the value bytes
     * @param string $raw     the whole record as it was encoded: the merkle tree hashes these exact bytes
     * @param string $rawType the type as it was encoded (BigSize): the merkle nonce leaf hashes it
     */
    public function __construct(
        public int $type,
        public string $value,
        public string $raw,
        public string $rawType,
    ) {}

    /**
     * Splits a TLV stream into records, enforcing the BOLT #1 rules every
     * reader must: minimal BigSize encodings, strictly increasing types, and
     * no length beyond the end of the stream.
     *
     * @return list<self>
     *
     * @throws \InvalidArgumentException when the stream is malformed
     *
     * @see https://github.com/lightning/bolts/blob/master/01-messaging.md#type-length-value-format
     */
    public static function parseStream(string $bytes): array
    {
        $reader = new ByteReader($bytes);
        $records = [];
        $previousType = -1;

        while (!$reader->isAtEnd()) {
            $start = \strlen($bytes) - $reader->remaining();
            $type = $reader->readBigSize();
            $typeEnd = \strlen($bytes) - $reader->remaining();
            $length = $reader->readBigSize();
            $value = $reader->read($length);

            // Strictly increasing also rules out a type that appears twice,
            // which would leave a reader to pick one of the two values.
            if ($type <= $previousType) {
                throw new \InvalidArgumentException(\sprintf('TLV type %d does not follow type %d in increasing order', $type, $previousType));
            }

            $previousType = $type;
            $records[] = new self(
                $type,
                $value,
                substr($bytes, $start, \strlen($bytes) - $reader->remaining() - $start),
                substr($bytes, $start, $typeEnd - $start),
            );
        }

        return $records;
    }
}
