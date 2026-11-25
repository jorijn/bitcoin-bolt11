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

namespace Tests\Jorijn\Bitcoin\Bolt12\Internal;

use Jorijn\Bitcoin\Bolt12\Internal\ByteReader;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
#[CoversClass(ByteReader::class)]
final class ByteReaderTest extends TestCase
{
    /**
     * The BigSize decoding vectors of BOLT #1, appendix A. The largest value
     * does not fit a PHP integer; no BOLT #12 field can need it.
     */
    #[DataProvider('provideBigSizeCases')]
    public function testBigSize(string $hex, ?int $expected): void
    {
        $reader = new ByteReader((string) hex2bin($hex));

        if (null === $expected) {
            $this->expectException(\InvalidArgumentException::class);
        }

        self::assertSame($expected, $reader->readBigSize());
        self::assertTrue($reader->isAtEnd());
    }

    /**
     * @return iterable<string, array{string, ?int}>
     */
    public static function provideBigSizeCases(): iterable
    {
        yield 'zero' => ['00', 0];

        yield 'one byte high' => ['fc', 252];

        yield 'two byte low' => ['fd00fd', 253];

        yield 'two byte high' => ['fdffff', 65535];

        yield 'four byte low' => ['fe00010000', 65536];

        yield 'four byte high' => ['feffffffff', 4294967295];

        yield 'eight byte low' => ['ff0000000100000000', 4294967296];

        yield 'eight byte high (beyond PHP_INT_MAX)' => ['ffffffffffffffffff', null];

        yield 'two byte not canonical' => ['fd00fc', null];

        yield 'four byte not canonical' => ['fe0000ffff', null];

        yield 'eight byte not canonical' => ['ff00000000ffffffff', null];

        yield 'two byte short read' => ['fd00', null];

        yield 'four byte short read' => ['feffff', null];

        yield 'eight byte short read' => ['ffffffffff', null];

        yield 'one byte no read' => ['', null];

        yield 'two byte no read' => ['fd', null];

        yield 'four byte no read' => ['fe', null];

        yield 'eight byte no read' => ['ff', null];
    }

    public function testFixedWidthIntegers(): void
    {
        $reader = new ByteReader((string) hex2bin('010203040506077fffffffffffffff'));

        self::assertSame(1, $reader->readU8());
        self::assertSame(0x0203, $reader->readU16());
        self::assertSame(0x04050607, $reader->readU32());
        self::assertSame(PHP_INT_MAX, $reader->readU64());
        self::assertSame(0, $reader->remaining());
    }

    #[DataProvider('provideTruncatedIntegersCases')]
    public function testTruncatedIntegers(string $hex, int $maxBytes, ?int $expected): void
    {
        if (null === $expected) {
            $this->expectException(\InvalidArgumentException::class);
        }

        self::assertSame($expected, (new ByteReader((string) hex2bin($hex)))->readTruncated($maxBytes));
    }

    /**
     * @return iterable<string, array{string, int, ?int}>
     */
    public static function provideTruncatedIntegersCases(): iterable
    {
        yield 'zero is no bytes' => ['', 8, 0];

        yield 'one byte' => ['01', 8, 1];

        yield 'four bytes as tu32' => ['ffffffff', 4, 4294967295];

        yield 'five bytes as tu32' => ['0100000000', 4, null];

        yield 'leading zero' => ['0001', 8, null];

        yield 'a single zero byte' => ['00', 8, null];

        yield 'beyond PHP_INT_MAX' => ['8000000000000000', 8, null];
    }

    public function testReadingPastTheEndFails(): void
    {
        $reader = new ByteReader('ab');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('truncated');

        $reader->read(3);
    }
}
