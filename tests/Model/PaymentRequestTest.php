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

        static::assertNull($paymentRequest->findTagByName('tag3'));
        static::assertSame($tag1, $paymentRequest->findTagByName('tag1'));
        static::assertSame($tag2, $paymentRequest->findTagByName('tag2'));
    }
}
