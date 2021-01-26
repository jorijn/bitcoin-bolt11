<?php

declare(strict_types=1);

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
