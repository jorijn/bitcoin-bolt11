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

use Jorijn\Bitcoin\Bolt11\Internal\Bech32;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Test vectors from BIP 173 (bech32) and BIP 350 (bech32m).
 *
 * @internal
 */
#[CoversClass(Bech32::class)]
final class Bech32Test extends TestCase
{
    #[DataProvider('provideDecodesValidStringsCases')]
    public function testDecodesValidStrings(string $string, int $checksum): void
    {
        [$hrp, $words] = Bech32::decode($string, $checksum);

        // Decoding and encoding again gives the lowercase original.
        self::assertSame(strtolower($string), Bech32::encode($hrp, $words, $checksum));
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function provideDecodesValidStringsCases(): iterable
    {
        foreach ([
            'A12UEL5L',
            'a12uel5l',
            'an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs',
            'abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw',
            '11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j',
            'split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w',
            '?1ezyfcl',
        ] as $string) {
            yield 'bech32 '.$string => [$string, Bech32::CHECKSUM_BECH32];
        }

        foreach ([
            'A1LQFN3A',
            'a1lqfn3a',
            'an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6',
            'abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx',
            '11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8',
            'split1checkupstagehandshakeupstreamerranterredcaperredlc445v',
            '?1v759aa',
        ] as $string) {
            yield 'bech32m '.$string => [$string, Bech32::CHECKSUM_BECH32M];
        }
    }

    #[DataProvider('provideRejectsInvalidStringsCases')]
    public function testRejectsInvalidStrings(string $string, int $checksum = Bech32::CHECKSUM_BECH32): void
    {
        $this->expectException(\InvalidArgumentException::class);

        Bech32::decode($string, $checksum);
    }

    /**
     * @return iterable<string, array{0: string, 1?: int}>
     */
    public static function provideRejectsInvalidStringsCases(): iterable
    {
        yield 'space in the human-readable part' => ["\x201nwldj5"];

        yield 'DEL in the human-readable part' => ["\x7f1axkwrx"];

        yield 'byte above ASCII in the human-readable part' => ["\x801eym55h"];

        yield 'no separator' => ['pzry9x0s0muk'];

        yield 'empty human-readable part' => ['1pzry9x0s0muk'];

        yield 'invalid data character' => ['x1b4n0q5v'];

        yield 'checksum too short' => ['li1dgmt3'];

        yield 'invalid character in the checksum' => ["de1lg7wt\xff"];

        yield 'checksum computed with an upper case human-readable part' => ['A1G7SGD8'];

        yield 'empty human-readable part, data only' => ['10a06t8'];

        yield 'mixed case' => ['a12UEL5L'];

        yield 'bech32 string checked as bech32m' => ['a12uel5l', Bech32::CHECKSUM_BECH32M];

        yield 'bech32m string checked as bech32' => ['a1lqfn3a'];
    }

    public function testHasNoLengthLimitUnlessAskedFor(): void
    {
        $long = Bech32::encode('ln', array_fill(0, 200, 0));

        self::assertCount(200, Bech32::decode($long)[1]);

        $this->expectException(\InvalidArgumentException::class);
        Bech32::decode($long, Bech32::CHECKSUM_BECH32, 90);
    }

    #[DataProvider('provideEncodesSegwitAddressesCases')]
    public function testEncodesSegwitAddresses(string $address, string $hrp, int $version, string $program): void
    {
        self::assertSame(strtolower($address), Bech32::encodeSegwitAddress($hrp, $version, (string) hex2bin($program)));
    }

    /**
     * @return iterable<string, array{string, string, int, string}>
     */
    public static function provideEncodesSegwitAddressesCases(): iterable
    {
        yield 'P2WPKH' => ['BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4', 'bc', 0, '751e76e8199196d454941c45d1b3a323f1433bd6'];

        yield 'P2WSH on testnet' => ['tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7', 'tb', 0, '1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262'];

        yield 'version 1, 40 bytes' => ['bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y', 'bc', 1, '751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6'];

        yield 'version 16, 2 bytes' => ['BC1SW50QGDZ25J', 'bc', 16, '751e'];

        yield 'version 2, 16 bytes' => ['bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs', 'bc', 2, '751e76e8199196d454941c45d1b3a323'];

        yield 'P2WSH with leading zeros' => ['tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy', 'tb', 0, '000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433'];

        yield 'P2TR on testnet' => ['tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c', 'tb', 1, '000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433'];

        yield 'P2TR' => ['bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0', 'bc', 1, '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'];
    }

    #[DataProvider('provideRejectsInvalidSegwitProgramsCases')]
    public function testRejectsInvalidSegwitPrograms(int $version, int $length): void
    {
        $this->expectException(\InvalidArgumentException::class);

        Bech32::encodeSegwitAddress('bc', $version, str_repeat("\x01", $length));
    }

    /**
     * @return iterable<string, array{int, int}>
     */
    public static function provideRejectsInvalidSegwitProgramsCases(): iterable
    {
        yield 'version 0 with 16 bytes' => [0, 16];

        yield 'version 0 with 21 bytes' => [0, 21];

        yield 'version 1 with 1 byte' => [1, 1];

        yield 'version 1 with 41 bytes' => [1, 41];

        yield 'version 17' => [17, 20];

        yield 'negative version' => [-1, 20];
    }

    public function testConvertsBitsWithAndWithoutPadding(): void
    {
        // 0xff is 11111111: one full 5-bit group and 3 leftover bits.
        self::assertSame([31, 28], Bech32::convertBits([0xFF], 8, 5, true));
        self::assertSame([31], Bech32::convertBits([0xFF], 8, 5, false));
        self::assertSame([0xFF], Bech32::convertBits([31, 28], 5, 8, false));
        self::assertSame("\xff", Bech32::wordsToBytes([31, 28]));
        self::assertSame("\xff\x00", Bech32::wordsToBytes([31, 28], true));
        self::assertSame('', Bech32::wordsToBytes([]));
    }
}
