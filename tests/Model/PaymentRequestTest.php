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

namespace Tests\Jorijn\Bitcoin\Bolt11\Model;

use Jorijn\Bitcoin\Bolt11\Model\PaymentRequest;
use Jorijn\Bitcoin\Bolt11\Model\Tag;
use PHPUnit\Framework\TestCase;

/**
 * @coversDefaultClass \Jorijn\Bitcoin\Bolt11\Model\PaymentRequest
 *
 * @internal
 */
final class PaymentRequestTest extends TestCase
{
    /**
     * @covers ::findTagByName
     * @covers ::getTags
     * @covers ::setTags
     *
     * @uses \Jorijn\Bitcoin\Bolt11\Model\Tag
     */
    public function testFindTagByName(): void
    {
        $paymentRequest = new PaymentRequest();

        $tag1 = new Tag();
        $tag1->setTagName('tag1');
        $tag2 = new Tag();
        $tag2->setTagName('tag2');

        $paymentRequest->setTags([$tag1, $tag2]);

        self::assertNull($paymentRequest->findTagByName('tag3'));
        self::assertSame($tag1, $paymentRequest->findTagByName('tag1'));
        self::assertSame($tag2, $paymentRequest->findTagByName('tag2'));
    }

    /**
     * @covers ::findTagsByName
     * @covers ::getTags
     * @covers ::setTags
     *
     * @uses \Jorijn\Bitcoin\Bolt11\Model\Tag
     */
    public function testFindTagsByName(): void
    {
        $paymentRequest = new PaymentRequest();

        $route1 = new Tag();
        $route1->setTagName(Tag::ROUTING_INFO);
        $description = new Tag();
        $description->setTagName(Tag::DESCRIPTION);
        $route2 = new Tag();
        $route2->setTagName(Tag::ROUTING_INFO);

        $paymentRequest->setTags([$route1, $description, $route2]);

        // All matches in invoice order, re-indexed from 0 so callers can use $tags[0].
        self::assertSame([$route1, $route2], $paymentRequest->findTagsByName(Tag::ROUTING_INFO));
        self::assertSame([$description], $paymentRequest->findTagsByName(Tag::DESCRIPTION));
        self::assertSame([], $paymentRequest->findTagsByName(Tag::FALLBACK_ADDRESS));
    }
}
