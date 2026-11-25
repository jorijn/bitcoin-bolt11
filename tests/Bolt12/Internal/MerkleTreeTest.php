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

use Jorijn\Bitcoin\Bolt11\Internal\Secp256k1;
use Jorijn\Bitcoin\Bolt12\Internal\ByteReader;
use Jorijn\Bitcoin\Bolt12\Internal\MerkleTree;
use Jorijn\Bitcoin\Bolt12\Internal\TlvRecord;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Tests\Jorijn\Bitcoin\Bolt12\Support\Bolt12Builder;

/**
 * root() builds the tree level by level; reconstructRoot() walks it
 * recursively. Agreeing on every size up to 40 leaves shows both describe
 * the same tree.
 *
 * @internal
 */
#[CoversClass(MerkleTree::class)]
#[UsesClass(TlvRecord::class)]
#[UsesClass(ByteReader::class)]
#[UsesClass(Secp256k1::class)]
final class MerkleTreeTest extends TestCase
{
    public function testReconstructedRootMatchesRootForEveryTreeSize(): void
    {
        for ($count = 1; $count <= 40; ++$count) {
            $records = self::records($count);
            self::assertSame(bin2hex(MerkleTree::root($records)), bin2hex(MerkleTree::reconstructRoot(self::leaves($records), [])), $count.' leaves');
        }
    }

    /**
     * Every way to hide leaves of trees up to 9 leaves, with the missing
     * hashes a writer would give: the reader must get the same root.
     */
    #[DataProvider('provideEveryHiddenSubsetRebuildsTheRootCases')]
    public function testEveryHiddenSubsetRebuildsTheRoot(int $count): void
    {
        $records = self::records($count);
        $leaves = self::leaves($records);
        $root = MerkleTree::root($records);

        // Every mask but the one hiding all leaves.
        for ($mask = 0; $mask < (1 << $count) - 1; ++$mask) {
            $shown = [];
            for ($i = 0; $i < $count; ++$i) {
                $shown[] = 0 === ($mask & (1 << $i));
            }

            $missing = [];
            self::write($leaves, $shown, 0, $count, $missing);
            $partial = array_map(static fn (string $leaf, bool $isShown): ?string => $isShown ? $leaf : null, $leaves, $shown);

            self::assertSame(bin2hex($root), bin2hex(MerkleTree::reconstructRoot($partial, $missing)), \sprintf('%d leaves, mask %b', $count, $mask));
        }
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideEveryHiddenSubsetRebuildsTheRootCases(): iterable
    {
        for ($count = 1; $count <= 9; ++$count) {
            yield $count.' leaves' => [$count];
        }
    }

    /**
     * @param list<?string> $leaves
     * @param list<string>  $missing
     */
    #[DataProvider('provideReconstructRootRejectsCases')]
    public function testReconstructRootRejects(array $leaves, array $missing, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        MerkleTree::reconstructRoot($leaves, $missing);
    }

    /**
     * @return iterable<string, array{list<?string>, list<string>, string}>
     */
    public static function provideReconstructRootRejectsCases(): iterable
    {
        $leaf = str_repeat("\1", 32);
        $hash = str_repeat("\2", 32);

        yield 'no leaves' => [[], [], 'there are no leaves'];

        yield 'only hidden leaves' => [[null, null, null], [$hash], 'every leaf is hidden'];

        yield 'too few missing hashes' => [[$leaf, null, null], [$hash], 'too few missing hashes'];

        yield 'too many missing hashes' => [[$leaf, null], [$hash, $hash], '2 missing hashes given, 1 used'];

        yield 'missing hashes with nothing hidden' => [[$leaf, $leaf], [$hash], '1 missing hashes given, 0 used'];
    }

    /**
     * $count records of odd types, so any count makes a valid stream.
     *
     * @return list<TlvRecord>
     */
    private static function records(int $count): array
    {
        $builder = Bolt12Builder::create();
        for ($i = 0; $i < $count; ++$i) {
            $builder = $builder->with(2 * $i + 1, 'field '.$i);
        }

        return TlvRecord::parseStream($builder->bytes());
    }

    /**
     * @param list<TlvRecord> $records
     *
     * @return list<string>
     */
    private static function leaves(array $records): array
    {
        $nonceTag = 'LnNonce'.$records[0]->raw;

        return array_map(static fn (TlvRecord $record): string => MerkleTree::leaf($record->raw, Secp256k1::taggedHash($nonceTag, $record->rawType)), $records);
    }

    /**
     * The writer's side: depth first, left to right, each node with exactly
     * one hidden side gives that side's hash.
     *
     * @param list<string> $leaves
     * @param list<bool>   $shown
     * @param list<string> $missing
     *
     * @return array{string, bool} the hash, and whether the subtree is all hidden
     */
    private static function write(array $leaves, array $shown, int $offset, int $count, array &$missing): array
    {
        if (1 === $count) {
            return [$leaves[$offset], !$shown[$offset]];
        }

        $leftCount = 1;
        while ($leftCount * 2 < $count) {
            $leftCount *= 2;
        }

        [$left, $leftHidden] = self::write($leaves, $shown, $offset, $leftCount, $missing);
        [$right, $rightHidden] = self::write($leaves, $shown, $offset + $leftCount, $count - $leftCount, $missing);

        if ($leftHidden !== $rightHidden) {
            $missing[] = $leftHidden ? $left : $right;
        }

        return [Secp256k1::taggedHash('LnBranch', strcmp($left, $right) < 0 ? $left.$right : $right.$left), $leftHidden && $rightHidden];
    }
}
