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
 * Reads the fundamental types of BOLT #1 from a byte string, front to back.
 * Every read checks that enough bytes are left, so a truncated message fails
 * with an exception instead of reading garbage.
 *
 * @internal not covered by the backward compatibility promise
 *
 * @see https://github.com/lightning/bolts/blob/master/01-messaging.md#fundamental-types
 */
final class ByteReader
{
    private int $offset = 0;

    public function __construct(private readonly string $bytes) {}

    public function isAtEnd(): bool
    {
        return $this->offset >= \strlen($this->bytes);
    }

    public function remaining(): int
    {
        return \strlen($this->bytes) - $this->offset;
    }

    /**
     * @throws \InvalidArgumentException when fewer than $length bytes are left
     */
    public function read(int $length): string
    {
        if ($length < 0 || $length > $this->remaining()) {
            throw new \InvalidArgumentException('message is truncated');
        }

        $bytes = substr($this->bytes, $this->offset, $length);
        $this->offset += $length;

        return $bytes;
    }

    public function readU8(): int
    {
        return \ord($this->read(1));
    }

    public function readU16(): int
    {
        return $this->unsigned($this->read(2));
    }

    public function readU32(): int
    {
        return $this->unsigned($this->read(4));
    }

    /**
     * A u64. PHP integers stop at 2^63 − 1, so larger values are rejected.
     *
     * @throws \InvalidArgumentException when the value does not fit in an int
     */
    public function readU64(): int
    {
        return $this->unsigned($this->read(8));
    }

    /**
     * BigSize: one byte below 0xfd, else a marker byte and 2, 4 or 8 bytes.
     * BOLT #1 requires the shortest form, so 0xfd followed by a value below
     * 0xfd (and so on) is rejected: otherwise one number would have several
     * encodings.
     *
     * @throws \InvalidArgumentException when it is truncated, not minimal or too large
     */
    public function readBigSize(): int
    {
        $first = $this->readU8();

        [$value, $minimum] = match ($first) {
            0xFD => [$this->readU16(), 0xFD],
            0xFE => [$this->readU32(), 0x10000],
            0xFF => [$this->readU64(), 0x100000000],
            default => [$first, 0],
        };

        if ($value < $minimum) {
            throw new \InvalidArgumentException('bigsize is not minimally encoded');
        }

        return $value;
    }

    /**
     * Converts the rest of the bytes as a truncated integer (tu16, tu32 or
     * tu64): big-endian without leading zero bytes, so zero is no bytes at all.
     *
     * @param int $maxBytes 2, 4 or 8
     *
     * @throws \InvalidArgumentException when it is too long, not minimal or too large
     */
    public function readTruncated(int $maxBytes): int
    {
        $bytes = $this->read($this->remaining());
        if (\strlen($bytes) > $maxBytes) {
            throw new \InvalidArgumentException(\sprintf('truncated integer is longer than %d bytes', $maxBytes));
        }

        if ('' !== $bytes && "\0" === $bytes[0]) {
            throw new \InvalidArgumentException('truncated integer is not minimally encoded');
        }

        return $this->unsigned($bytes);
    }

    /**
     * @throws \InvalidArgumentException when the value does not fit in an int
     */
    private function unsigned(string $bytes): int
    {
        $value = 0;
        foreach (str_split($bytes) as $byte) {
            if ($value > (PHP_INT_MAX >> 8)) {
                throw new \InvalidArgumentException('integer does not fit in 63 bits');
            }

            $value = ($value << 8) | \ord($byte);
        }

        return $value;
    }
}
