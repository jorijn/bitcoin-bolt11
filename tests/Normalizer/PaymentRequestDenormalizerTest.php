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

use BitWasp\Bitcoin\Network\NetworkInterface;
use Jorijn\Bitcoin\Bolt11\Model\Tag;
use Jorijn\Bitcoin\Bolt11\Model\TagInterface;
use Jorijn\Bitcoin\Bolt11\Normalizer\PaymentRequestDenormalizer;
use Jorijn\Bitcoin\Bolt11\Normalizer\TagDenormalizer;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * @coversDefaultClass \Jorijn\Bitcoin\Bolt11\Normalizer\PaymentRequestDenormalizer
 *
 * @covers ::__construct
 *
 * @uses \Jorijn\Bitcoin\Bolt11\Model\PaymentRequest
 * @uses \Jorijn\Bitcoin\Bolt11\Normalizer\DenormalizerTrait
 *
 * @internal
 */
final class PaymentRequestDenormalizerTest extends TestCase
{
    /** @var PaymentRequestDenormalizer */
    private $denormalizer;

    /** @var MockObject|TagDenormalizer */
    private $tagDenormalizer;

    protected function setUp(): void
    {
        parent::setUp();

        $this->tagDenormalizer = $this->createMock(TagDenormalizer::class);
        $this->denormalizer = new PaymentRequestDenormalizer($this->tagDenormalizer);
    }

    /**
     * @covers ::denormalize
     */
    public function testDenormalizeWithTags(): void
    {
        $denormalizedTags = [$this->createMock(TagInterface::class)];

        $data = [
            'prefix' => $prefix = 'prefix_'.random_int(1, 1000),
            'network' => $network = $this->createMock(NetworkInterface::class),
            'timestamp' => $timestamp = time(),
            'timestamp_string' => $timestampString = date(\DateTime::ATOM, $timestamp),
            'payee_node_key' => $payeeNodeKey = 'pnk_'.random_int(1000, 2000),
            'signature' => $signature = 'sig_'.random_int(1000, 2000),
            'recovery_flag' => $recoveryFlag = random_int(1, 3),
            'tags' => $tags = ['random_tag_'.random_int(1000, 2000)],
        ];

        $this->tagDenormalizer
            ->expects(self::once())
            ->method('denormalize')
            ->with($tags, Tag::class.'[]')
            ->willReturn($denormalizedTags)
        ;

        $paymentRequest = $this->denormalizer->denormalize($data);

        self::assertSame($prefix, $paymentRequest->getPrefix());
        self::assertSame($network, $paymentRequest->getNetwork());
        self::assertSame($timestamp, $paymentRequest->getTimestamp());
        self::assertSame($timestampString, $paymentRequest->getTimestampDateTime()->format(\DateTime::ATOM));
        self::assertSame($payeeNodeKey, $paymentRequest->getPayeeNodeKey());
        self::assertSame($signature, $paymentRequest->getSignature());
        self::assertSame($recoveryFlag, $paymentRequest->getRecoveryFlag());
        self::assertSame($denormalizedTags, $paymentRequest->getTags());
    }

    /**
     * @covers ::denormalize
     */
    public function testDenormalizeWithoutTags(): void
    {
        $data = [
            'prefix' => $prefix = 'prefix_'.random_int(1, 1000),
            'network' => $network = $this->createMock(NetworkInterface::class),
            'satoshis' => $satoshis = 1 === random_int(1, 3) ? random_int(1000, 5000) : null,
            'milli_satoshis' => $milliSatoshis = null !== $satoshis ? $satoshis * 1000 : null,
            'timestamp' => $timestamp = time(),
            'timestamp_string' => $timestampString = date(\DateTime::ATOM, $timestamp),
            'payee_node_key' => $payeeNodeKey = 'pnk_'.random_int(1000, 2000),
            'signature' => $signature = 'sig_'.random_int(1000, 2000),
            'recovery_flag' => $recoveryFlag = random_int(1, 3),
            'expiry_timestamp' => $expiryTimestamp = 1 === random_int(1, 3) ? time() + 3600 : null,
            'expiry_datetime' => $expiryDateTime = null !== $expiryTimestamp ? date(
                \DateTime::ATOM,
                $expiryTimestamp
            ) : null,
        ];

        $paymentRequest = $this->denormalizer->denormalize($data);

        self::assertSame($prefix, $paymentRequest->getPrefix());
        self::assertSame($network, $paymentRequest->getNetwork());
        self::assertSame($satoshis, $paymentRequest->getSatoshis());
        self::assertSame($milliSatoshis, $paymentRequest->getMilliSatoshis());
        self::assertSame($timestamp, $paymentRequest->getTimestamp());
        self::assertSame($payeeNodeKey, $paymentRequest->getPayeeNodeKey());
        self::assertSame($signature, $paymentRequest->getSignature());
        self::assertSame($recoveryFlag, $paymentRequest->getRecoveryFlag());
        self::assertSame($expiryTimestamp, $paymentRequest->getExpiryTimestamp());

        self::assertSame(
            $timestampString,
            null !== $timestampString
                ? $paymentRequest->getTimestampDateTime()->format(\DateTime::ATOM)
                : $paymentRequest->getTimestampDateTime()
        );

        self::assertSame(
            $expiryDateTime,
            null !== $expiryDateTime
                ? $paymentRequest->getExpiryDateTime()->format(\DateTime::ATOM)
                : $paymentRequest->getExpiryDateTime()
        );
    }
}
