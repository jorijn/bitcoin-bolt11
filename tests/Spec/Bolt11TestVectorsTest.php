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

namespace Tests\Jorijn\Bitcoin\Bolt11\Spec;

use Jorijn\Bitcoin\Bolt11\Encoder\PaymentRequestDecoder;
use Jorijn\Bitcoin\Bolt11\Exception\PaymentRequestDecodeException;
use Jorijn\Bitcoin\Bolt11\Normalizer\PaymentRequestDenormalizer;
use PHPUnit\Framework\TestCase;

/**
 * Runs the official BOLT #11 test vectors (see tests/Fixtures/README.md).
 *
 * Vectors the library currently gets wrong are listed in KNOWN_FAILURES and run
 * in a separate group, so the default suite stays green while every regression
 * in the vectors that do pass is caught. The known failures are a to-do list:
 * once a fix lands, its index moves out of KNOWN_FAILURES and into the gate.
 *
 * @coversDefaultClass \Jorijn\Bitcoin\Bolt11\Encoder\PaymentRequestDecoder
 *
 * @covers ::__construct
 * @covers ::decode
 * @covers ::decodePaymentRequest
 * @covers \Jorijn\Bitcoin\Bolt11\Normalizer\PaymentRequestDenormalizer
 *
 * @internal
 */
final class Bolt11TestVectorsTest extends TestCase
{
    private const FIXTURE = __DIR__.'/../Fixtures/bolt11-invoice-test.json';

    /**
     * Index in the fixture => why the current decoder gets it wrong.
     * All of these are invalid invoices that the decoder accepts.
     */
    private const KNOWN_FAILURES = [
        16 => 'unknown even feature bit is not rejected',
        17 => '`n` field of invalid length is skipped instead of rejected',
        18 => 'missing `p` field is not rejected',
        19 => 'two distinct `p` fields are not rejected',
        20 => 'the same `p` field twice is not rejected',
        21 => 'two distinct `s` fields are not rejected',
        29 => 'missing `s` field is not rejected',
    ];

    /**
     * @dataProvider provideVectorCases
     */
    public function testVector(string $invoice, bool $valid, string $description): void
    {
        $this->assertVectorBehaves($invoice, $valid, $description);
    }

    public static function provideVectorCases(): iterable
    {
        foreach (self::loadVectors() as $index => $vector) {
            if (!\array_key_exists($index, self::KNOWN_FAILURES)) {
                yield self::label($index, $vector) => [$vector['invoice'], $vector['valid'], $vector['description']];
            }
        }
    }

    /**
     * Not part of the default suite (excluded in phpunit.xml.dist). CI runs it
     * in a separate job that reports how many still fail, and fails only once
     * one of them passes, so a fixed vector gets moved into the gate.
     *
     * @group spec-known-failure
     *
     * @dataProvider provideKnownFailureCases
     */
    public function testKnownFailure(string $invoice, bool $valid, string $description): void
    {
        $this->assertVectorBehaves($invoice, $valid, $description);
    }

    public static function provideKnownFailureCases(): iterable
    {
        $vectors = self::loadVectors();
        foreach (self::KNOWN_FAILURES as $index => $reason) {
            yield self::label($index, $vectors[$index]).' ('.$reason.')' => [
                $vectors[$index]['invoice'],
                $vectors[$index]['valid'],
                $vectors[$index]['description'],
            ];
        }
    }

    private function assertVectorBehaves(string $invoice, bool $valid, string $description): void
    {
        $decoder = new PaymentRequestDecoder();
        $denormalizer = new PaymentRequestDenormalizer();

        if ($valid) {
            // A valid vector must decode and denormalize without any exception.
            $paymentRequest = $denormalizer->denormalize($decoder->decode($invoice));
            self::assertNotEmpty($paymentRequest->getPayeeNodeKey(), $description);

            return;
        }

        // An invalid vector must be rejected with the library's own exception
        // type, so callers can rely on a single catch for untrusted input.
        try {
            $denormalizer->denormalize($decoder->decode($invoice));
        } catch (PaymentRequestDecodeException $exception) {
            $this->addToAssertionCount(1);

            return;
        }

        self::fail('invalid invoice was accepted: '.$description);
    }

    /**
     * @return array<int, array{description: string, valid: bool, invoice: string}>
     */
    private static function loadVectors(): array
    {
        return json_decode((string) file_get_contents(self::FIXTURE), true, 512, JSON_THROW_ON_ERROR);
    }

    /**
     * @param array{description: string, valid: bool, invoice: string} $vector
     */
    private static function label(int $index, array $vector): string
    {
        // Descriptions are long and not unique, so prefix the fixture index.
        return \sprintf('#%02d %s: %s', $index, $vector['valid'] ? 'valid' : 'invalid', mb_strimwidth($vector['description'], 0, 80, '...'));
    }
}
