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

namespace Tests\Jorijn\Bitcoin\Bolt11\Internal;

use Jorijn\Bitcoin\Bolt11\Internal\Base58;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
#[CoversClass(Base58::class)]
final class Base58Test extends TestCase
{
    /**
     * Vectors from Bitcoin Core (src/test/data/base58_encode_decode.json).
     */
    #[DataProvider('provideEncodeCases')]
    public function testEncode(string $hex, string $expected): void
    {
        self::assertSame($expected, Base58::encode((string) hex2bin($hex)));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideEncodeCases(): iterable
    {
        yield 'empty' => ['', ''];

        yield 'one byte' => ['61', '2g'];

        yield 'three bytes' => ['626262', 'a3gV'];

        yield 'another three bytes' => ['636363', 'aPEr'];

        yield 'text' => ['73696d706c792061206c6f6e6720737472696e67', '2cFupjhnEsSn59qHXstmK2ffpLv2'];

        yield 'address with a leading zero byte' => ['00eb15231dfceb60925886b67d065299925915aeb172c06647', '1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L'];

        yield 'five bytes' => ['516b6fcd0f', 'ABnLTmg'];

        yield 'nine bytes' => ['bf4f89001e670274dd', '3SEo3LWLoPntC'];

        yield 'four bytes' => ['572e4794', '3EFU7m'];

        yield 'ten bytes' => ['ecac89cad93923c02321', 'EJDM8drfXA6uyA'];

        yield 'leading byte below 0x58' => ['10c8511e', 'Rt5zm'];

        yield 'only zero bytes' => ['00000000000000000000', '1111111111'];
    }

    public function testEncodeCheck(): void
    {
        // The fallback addresses of BOLT #11 vectors 5 (P2PKH) and 6 (P2SH).
        self::assertSame('1RustyRX2oai4EYYDpQGWvEL62BBGqN9T', Base58::encodeCheck(0x00, (string) hex2bin('04b61f7dc1ea0dc99424464cc4064dc564d91e89')));
        self::assertSame('3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX', Base58::encodeCheck(0x05, (string) hex2bin('8f55563b9a19f321c211e9b9f38cdf686ea07845')));
    }
}
