<?php

declare(strict_types=1);

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
    protected $denormalizer;
    /** @var MockObject|TagDenormalizer */
    protected $tagDenormalizer;

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
            ->expects(static::once())
            ->method('denormalize')
            ->with($tags, Tag::class.'[]')
            ->willReturn($denormalizedTags)
        ;

        $paymentRequest = $this->denormalizer->denormalize($data);

        static::assertSame($prefix, $paymentRequest->getPrefix());
        static::assertSame($network, $paymentRequest->getNetwork());
        static::assertSame($timestamp, $paymentRequest->getTimestamp());
        static::assertSame($timestampString, $paymentRequest->getTimestampDateTime()->format(\DateTime::ATOM));
        static::assertSame($payeeNodeKey, $paymentRequest->getPayeeNodeKey());
        static::assertSame($signature, $paymentRequest->getSignature());
        static::assertSame($recoveryFlag, $paymentRequest->getRecoveryFlag());
        static::assertSame($denormalizedTags, $paymentRequest->getTags());
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

        static::assertSame($prefix, $paymentRequest->getPrefix());
        static::assertSame($network, $paymentRequest->getNetwork());
        static::assertSame($satoshis, $paymentRequest->getSatoshis());
        static::assertSame($milliSatoshis, $paymentRequest->getMilliSatoshis());
        static::assertSame($timestamp, $paymentRequest->getTimestamp());
        static::assertSame($payeeNodeKey, $paymentRequest->getPayeeNodeKey());
        static::assertSame($signature, $paymentRequest->getSignature());
        static::assertSame($recoveryFlag, $paymentRequest->getRecoveryFlag());
        static::assertSame($expiryTimestamp, $paymentRequest->getExpiryTimestamp());

        static::assertSame(
            $timestampString,
            null !== $timestampString
                ? $paymentRequest->getTimestampDateTime()->format(\DateTime::ATOM)
                : $paymentRequest->getTimestampDateTime()
        );

        static::assertSame(
            $expiryDateTime,
            null !== $expiryDateTime
                ? $paymentRequest->getExpiryDateTime()->format(\DateTime::ATOM)
                : $paymentRequest->getExpiryDateTime()
        );
    }
}
