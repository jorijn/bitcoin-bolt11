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

namespace Tests\Jorijn\Bitcoin\Bolt11\Normalizer;

use Jorijn\Bitcoin\Bolt11\Encoder\PaymentRequestDecoder;
use Jorijn\Bitcoin\Bolt11\Model\FallbackAddress;
use Jorijn\Bitcoin\Bolt11\Model\RoutingInfo;
use Jorijn\Bitcoin\Bolt11\Model\Tag;
use Jorijn\Bitcoin\Bolt11\Model\UnknownTag;
use Jorijn\Bitcoin\Bolt11\Normalizer\FallbackAddressDenormalizer;
use Jorijn\Bitcoin\Bolt11\Normalizer\RoutingInfoDenormalizer;
use Jorijn\Bitcoin\Bolt11\Normalizer\TagDenormalizer;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * @coversDefaultClass \Jorijn\Bitcoin\Bolt11\Normalizer\TagDenormalizer
 * @covers ::__construct
 *
 * @uses \Jorijn\Bitcoin\Bolt11\Normalizer\DenormalizerTrait
 * @uses \Jorijn\Bitcoin\Bolt11\Model\Tag
 * @uses \Jorijn\Bitcoin\Bolt11\Model\UnknownTag
 *
 * @internal
 */
final class TagDenormalizerTest extends TestCase
{
    /** @var FallbackAddressDenormalizer|MockObject */
    protected $fallbackAddressDenormalizer;

    /** @var MockObject|RoutingInfoDenormalizer */
    protected $routingInfoDenormalizer;

    /** @var TagDenormalizer */
    protected $tagDenormalizer;

    protected function setUp(): void
    {
        parent::setUp();

        $this->fallbackAddressDenormalizer = $this->createMock(FallbackAddressDenormalizer::class);
        $this->routingInfoDenormalizer = $this->createMock(RoutingInfoDenormalizer::class);
        $this->tagDenormalizer = new TagDenormalizer(
            $this->fallbackAddressDenormalizer,
            $this->routingInfoDenormalizer,
        );
    }

    /**
     * @covers ::denormalize
     * @covers ::denormalizeTag
     */
    public function testUnknownTag(): void
    {
        $tag = $this->tagDenormalizer->denormalize([
            'tag_name' => PaymentRequestDecoder::NAME_UNKNOWN_TAG,
            'data' => [
                'tag_code' => $tagCode = random_int(15, 30),
                'words' => $words = 'words'.random_int(1000, 2000),
            ],
        ], Tag::class);

        static::assertInstanceOf(UnknownTag::class, $tag);
        static::assertSame((string) $tagCode, $tag->getTagName());
        static::assertSame($words, $tag->getData());
    }

    /**
     * @covers ::denormalize
     * @covers ::denormalizeTag
     */
    public function testArrayDenormalize(): void
    {
        $tags = $this->tagDenormalizer->denormalize([
            [
                'tag_name' => $tagName = 'tag_name'.random_int(1000, 2000),
                'data' => $data = 'data'.random_int(1000, 2000),
            ],
        ], Tag::class.'[]');

        static::assertNotEmpty($tags);
        static::assertInstanceOf(Tag::class, $tags[0]);
        static::assertSame($tagName, $tags[0]->getTagName());
        static::assertSame($data, $tags[0]->getData());
    }

    /**
     * @covers ::denormalize
     * @covers ::denormalizeTag
     */
    public function testRegularDenormalize(): void
    {
        $tag = $this->tagDenormalizer->denormalize([
            'tag_name' => $tagName = 'tag_name'.random_int(1000, 2000),
            'data' => $data = 'data'.random_int(1000, 2000),
        ], Tag::class);

        static::assertInstanceOf(Tag::class, $tag);
        static::assertSame($tagName, $tag->getTagName());
        static::assertSame($data, $tag->getData());
    }

    /**
     * @covers ::denormalize
     * @covers ::denormalizeTag
     */
    public function testRoutingInfoArray(): void
    {
        $inputArray = [random_int(15, 30), random_int(15, 30)];
        $routingInfo1 = $this->createMock(RoutingInfo::class);
        $routingInfo2 = $this->createMock(RoutingInfo::class);

        $this->routingInfoDenormalizer
            ->expects(static::once())
            ->method('denormalize')
            ->with($inputArray, RoutingInfo::class.'[]')
            ->willReturn([$routingInfo1, $routingInfo2])
        ;

        $tag = $this->tagDenormalizer->denormalize([
            'tag_name' => Tag::ROUTING_INFO,
            'data' => $inputArray,
        ], Tag::class);

        static::assertInstanceOf(Tag::class, $tag);
        static::assertSame(Tag::ROUTING_INFO, $tag->getTagName());
        static::assertSame([$routingInfo1, $routingInfo2], $tag->getData());
    }

    /**
     * @covers ::denormalize
     * @covers ::denormalizeTag
     */
    public function testFallbackAddress(): void
    {
        $inputArray = [random_int(15, 30), random_int(15, 30)];
        $fallbackAddress = $this->createMock(FallbackAddress::class);

        $this->fallbackAddressDenormalizer
            ->expects(static::once())
            ->method('denormalize')
            ->with($inputArray)
            ->willReturn($fallbackAddress)
        ;

        $tag = $this->tagDenormalizer->denormalize([
            'tag_name' => Tag::FALLBACK_ADDRESS,
            'data' => $inputArray,
        ], Tag::class);

        static::assertInstanceOf(Tag::class, $tag);
        static::assertSame(Tag::FALLBACK_ADDRESS, $tag->getTagName());
        static::assertSame($fallbackAddress, $tag->getData());
    }
}
