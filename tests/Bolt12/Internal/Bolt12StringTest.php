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

use Jorijn\Bitcoin\Bolt11\Internal\Bech32;
use Jorijn\Bitcoin\Bolt12\Internal\Bolt12String;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * The format-string spec vectors run in Bolt12TestVectorsTest; these cover
 * the rest of the encoding rules.
 *
 * @internal
 */
#[CoversClass(Bolt12String::class)]
#[UsesClass(Bech32::class)]
final class Bolt12StringTest extends TestCase
{
    public function testRoundTrips(): void
    {
        foreach (['', "\x00", "\xFF\x01", random_bytes(33), random_bytes(100)] as $bytes) {
            $string = Bolt12String::encode('lno', $bytes);

            self::assertSame(['lno', $bytes], Bolt12String::decode($string));
            self::assertSame(['lno', $bytes], Bolt12String::decode(strtoupper($string)));
        }
    }

    #[DataProvider('provideRejectsCases')]
    public function testRejects(string $string, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        Bolt12String::decode($string);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideRejectsCases(): iterable
    {
        yield 'no separator' => ['lnoqqqq', 'no "1" separator'];

        yield 'no prefix' => ['1qqqq', 'no "1" separator or no prefix'];

        yield 'character outside the charset' => ['lno1qqbq', 'invalid character "b"'];

        yield 'space without a "+"' => ['lno1qq qq', 'invalid characters'];

        yield 'non-ASCII' => ["lno1qq\u{e9}", 'invalid characters'];

        yield 'mixed case' => ['lno1QQqq', 'mixed case'];

        yield '"+" next to the separator' => ['lno+1qq', '"+" may only join'];

        yield 'padding of five bits' => ['lno1q', 'invalid padding'];

        yield 'non-zero padding bits' => ['lno1qp', 'invalid padding'];
    }
}
