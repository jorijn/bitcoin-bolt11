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

namespace Tests\Jorijn\Bitcoin\Bolt12;

use Jorijn\Bitcoin\Bolt11\Exception\ExceptionInterface;
use Jorijn\Bitcoin\Bolt11\Internal\Secp256k1;
use Jorijn\Bitcoin\Bolt12\Exception\Bolt12DecodeException;
use Jorijn\Bitcoin\Bolt12\Exception\InvalidEncodingException;
use Jorijn\Bitcoin\Bolt12\Exception\InvalidFieldException;
use Jorijn\Bitcoin\Bolt12\Exception\InvalidSignatureException;
use Jorijn\Bitcoin\Bolt12\Exception\MalformedTlvException;
use Jorijn\Bitcoin\Bolt12\Exception\UnknownRequiredFieldException;
use Jorijn\Bitcoin\Bolt12\Internal\Bolt12String;
use Jorijn\Bitcoin\Bolt12\Internal\ByteReader;
use Jorijn\Bitcoin\Bolt12\Internal\FieldReader;
use Jorijn\Bitcoin\Bolt12\Internal\MerkleTree;
use Jorijn\Bitcoin\Bolt12\Internal\TlvRecord;
use Jorijn\Bitcoin\Bolt12\Model\Features;
use Jorijn\Bitcoin\Bolt12\Model\PayerProof;
use Jorijn\Bitcoin\Bolt12\Model\UnknownField;
use Jorijn\Bitcoin\Bolt12\PayerProofDecoder;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Tests\Jorijn\Bitcoin\Bolt12\Support\Bolt12Builder;
use Tests\Jorijn\Bitcoin\Bolt12\Support\PayerProofBuilder;

/**
 * Tests each reader rule for payer proofs with a proof that is valid except
 * for the one thing under test. PayerProofBuilder re-signs every proof after
 * the change, so a test fails on its own rule and not on the proof signature.
 *
 * @internal
 */
#[CoversClass(PayerProofDecoder::class)]
#[CoversClass(PayerProof::class)]
#[CoversClass(FieldReader::class)]
#[UsesClass(Bolt12String::class)]
#[UsesClass(ByteReader::class)]
#[UsesClass(TlvRecord::class)]
#[UsesClass(MerkleTree::class)]
#[UsesClass(Features::class)]
#[UsesClass(UnknownField::class)]
#[UsesClass(Secp256k1::class)]
#[UsesClass(Bolt12DecodeException::class)]
#[UsesClass(UnknownRequiredFieldException::class)]
final class PayerProofDecoderTest extends TestCase
{
    /** The first_node_id key of the vectors (0x43 repeated): a node that is not the issuer. */
    private const OTHER_NODE_SECRET = '4343434343434343434343434343434343434343434343434343434343434343';

    private PayerProofDecoder $decoder;

    protected function setUp(): void
    {
        $this->decoder = new PayerProofDecoder();
    }

    public function testDecodesAMinimalProof(): void
    {
        $proof = $this->decoder->decode(PayerProofBuilder::forInvoice()->encode());

        self::assertSame(Bolt12Builder::PAYER_ID, $proof->getPayerId());
        self::assertSame(Bolt12Builder::ISSUER_ID, $proof->getNodeId());
        self::assertSame(PayerProofBuilder::PREIMAGE, $proof->getPreimage());
        self::assertSame(hash('sha256', (string) hex2bin(PayerProofBuilder::PREIMAGE)), $proof->getPaymentHash());
        self::assertSame(128, \strlen($proof->getInvoiceSignature()));
        self::assertSame(128, \strlen($proof->getProofSignature()));

        // Only what a writer must show: the payer id, payment hash and node id.
        self::assertSame([88, 168, 176], array_keys($proof->getDisclosedFields()));
        // invreq_metadata, offer_description, offer_issuer_id, invreq_amount,
        // invoice_paths, invoice_blindedpay, invoice_created_at, invoice_amount.
        self::assertSame(8, $proof->getOmittedFieldCount());

        self::assertNull($proof->getNote());
        self::assertNull($proof->getAmount());
        self::assertNull($proof->getCreatedAt());
        self::assertNull($proof->getDescription());
        self::assertNull($proof->getIssuer());
        self::assertNull($proof->getIssuerId());
        self::assertNull($proof->getPayerNote());
        self::assertNull($proof->getQuantity());
        self::assertSame([], $proof->getFeatures()->getBits());
        self::assertSame([], $proof->getUnknownFields());
    }

    public function testReadsTheFieldsAPayerShows(): void
    {
        $invoice = Bolt12Builder::invoice()
            ->with(18, 'example.com')
            ->withInt(20, 5)
            ->withInt(86, 2)
            ->with(89, 'Gift wrap, please')
            ->with(174, "\x02\x00\x00") // bit 17: optional multi-part payments
        ;

        $proof = $this->decoder->decode(PayerProofBuilder::forInvoice($invoice)->includingAll()->withNote('for order 1234')->encode());

        self::assertSame('for order 1234', $proof->getNote());
        self::assertSame(1000, $proof->getAmount());
        self::assertSame(Bolt12Builder::CREATED_AT, $proof->getCreatedAt()?->getTimestamp());
        self::assertSame('Test vectors', $proof->getDescription());
        self::assertSame('example.com', $proof->getIssuer());
        self::assertSame(Bolt12Builder::ISSUER_ID, $proof->getIssuerId());
        self::assertSame('Gift wrap, please', $proof->getPayerNote());
        self::assertSame(2, $proof->getQuantity());
        self::assertSame([17], $proof->getFeatures()->getBits());
        // Only invreq_metadata is left out.
        self::assertSame(1, $proof->getOmittedFieldCount());
        self::assertSame(bin2hex('example.com'), $proof->getDisclosedFields()[18]);
    }

    public function testToArray(): void
    {
        $proof = $this->decoder->decode(PayerProofBuilder::forInvoice()->including(10, 164, 170)->withNote('hi')->encode());

        $expected = [
            'payer_id' => Bolt12Builder::PAYER_ID,
            'node_id' => Bolt12Builder::ISSUER_ID,
            'payment_hash' => $proof->getPaymentHash(),
            'preimage' => PayerProofBuilder::PREIMAGE,
            'invoice_signature' => $proof->getInvoiceSignature(),
            'proof_signature' => $proof->getProofSignature(),
            'note' => 'hi',
            'amount' => 1000,
            'created_at' => '2023-11-14T22:13:20+00:00',
            'description' => 'Test vectors',
            'issuer' => null,
            'issuer_id' => null,
            'payer_note' => null,
            'quantity' => null,
            'features' => [],
            'disclosed_fields' => [
                10 => bin2hex('Test vectors'),
                88 => Bolt12Builder::PAYER_ID,
                164 => '6553f100',
                168 => $proof->getPaymentHash(),
                170 => '03e8',
                176 => Bolt12Builder::ISSUER_ID,
            ],
            'omitted_field_count' => 5,
            'unknown_fields' => [],
        ];

        self::assertSame($expected, $proof->toArray());
        self::assertSame($expected, $proof->jsonSerialize());
    }

    public function testKeepsUnknownOddFields(): void
    {
        $invoice = Bolt12Builder::invoice()->with(3_000_000_001, 'odd invoice field');
        $proof = $this->decoder->decode(
            PayerProofBuilder::forInvoice($invoice)
                ->including(3_000_000_001)
                ->with(243, 'odd signature-range field')
                ->with(1007, 'odd proof field')
                ->encode(),
        );

        // An odd field in the invoice ranges is part of the signed invoice.
        self::assertSame(bin2hex('odd invoice field'), $proof->getDisclosedFields()[3_000_000_001]);
        self::assertSame(
            [['type' => 243, 'value' => bin2hex('odd signature-range field')], ['type' => 1007, 'value' => bin2hex('odd proof field')]],
            array_map(static fn (UnknownField $field): array => $field->toArray(), $proof->getUnknownFields()),
        );
    }

    /**
     * A shown field 239 followed by an omitted one: the marker jumps past the
     * signature range, as Core Lightning writes it, instead of the 240 the
     * writer rule would give.
     */
    public function testMarkerAfterAShownField239JumpsPastTheSignatureRange(): void
    {
        $invoice = Bolt12Builder::invoice()->with(239, 'odd')->with(3_000_000_001, 'odd');
        $builder = PayerProofBuilder::forInvoice($invoice)->including(239);

        $markers = $this->markers($builder);
        self::assertSame(1_000_000_000, end($markers));
        self::assertSame(9, $this->decoder->decode($builder->encode())->getOmittedFieldCount());

        $markers[\count($markers) - 1] = 240;

        $this->expectException(InvalidFieldException::class);
        $this->expectExceptionMessage('proof_omitted_tlvs contains 240, outside the invoice ranges');

        $this->decoder->decode($builder->with(1002, implode('', array_map(Bolt12Builder::bigSize(...), $markers)))->encode());
    }

    /**
     * Invoice features are reported, not enforced: the invoice was paid, so
     * a feature this library does not know makes the proof no less true.
     */
    public function testAcceptsUnknownRequiredInvoiceFeatures(): void
    {
        // Bit 100: even, so required, and unknown.
        $features = "\x10".str_repeat("\0", 12);
        $proof = $this->decoder->decode(PayerProofBuilder::forInvoice(Bolt12Builder::invoice()->with(174, $features))->encode());

        self::assertSame([100], $proof->getFeatures()->getBits());
    }

    public function testRejectsAProofSignatureOfTheWrongLength(): void
    {
        $this->expectException(MalformedTlvException::class);
        $this->expectExceptionMessage('proof_signature must be 64 bytes');

        $this->decoder->decode(PayerProofBuilder::forInvoice()->build(null)->with(241, str_repeat("\1", 63))->encode('lnp'));
    }

    public function testEveryFailureIsABolt12DecodeException(): void
    {
        try {
            $this->decoder->decode('lnp1qqqq');
            self::fail('expected an exception');
        } catch (Bolt12DecodeException $exception) {
            self::assertInstanceOf(ExceptionInterface::class, $exception);
        }
    }

    /**
     * @param class-string<Bolt12DecodeException> $exception
     */
    #[DataProvider('provideRejectsCases')]
    public function testRejects(string $proof, string $exception, string $message): void
    {
        $this->expectException($exception);
        $this->expectExceptionMessage($message);

        $this->decoder->decode($proof);
    }

    /**
     * @return iterable<string, array{string, class-string<Bolt12DecodeException>, string}>
     */
    public static function provideRejectsCases(): iterable
    {
        $proof = PayerProofBuilder::forInvoice();

        yield 'an invoice' => [
            Bolt12Builder::invoice()->sign('invoice', Bolt12Builder::ISSUER_SECRET)->encode('lni'),
            InvalidEncodingException::class,
            'expected prefix "lnp", got "lni"',
        ];

        yield 'invalid characters' => ['lnp1bbbb', InvalidEncodingException::class, 'invalid character'];

        yield 'an empty proof' => [Bolt12String::encode('lnp', ''), MalformedTlvException::class, 'message is empty'];

        yield 'a broken TLV stream' => [Bolt12String::encode('lnp', "\x01\x05ab"), MalformedTlvException::class, 'message is truncated'];

        yield 'an unknown even proof field' => [$proof->with(1006, 'x')->encode(), UnknownRequiredFieldException::class, 'unknown even TLV type 1006'];

        yield 'an unknown even invoice field' => [
            PayerProofBuilder::forInvoice(Bolt12Builder::invoice()->with(24, 'x'))->including(24)->encode(),
            UnknownRequiredFieldException::class,
            'unknown even TLV type 24',
        ];

        yield 'an invalid payer id' => [
            $proof->with(88, "\x02".str_repeat("\xff", 32))->encode(),
            InvalidFieldException::class,
            'invreq_payer_id is not a valid public key',
        ];

        yield 'a preimage of the wrong length' => [$proof->with(1001, str_repeat("\1", 31))->encode(), MalformedTlvException::class, 'proof_preimage must be 32 bytes'];

        yield 'a malformed proof_omitted_tlvs' => [$proof->with(1002, "\xfd\x00\x01")->encode(), MalformedTlvException::class, 'proof_omitted_tlvs is malformed'];

        yield 'leaf hashes that are not 32 bytes each' => [$proof->with(1004, str_repeat("\0", 33))->encode(), MalformedTlvException::class, 'proof_leaf_hashes is not a list of 32-byte hashes'];

        yield 'missing hashes that are not 32 bytes each' => [$proof->with(1003, str_repeat("\0", 31))->encode(), MalformedTlvException::class, 'proof_missing_hashes is not a list of 32-byte hashes'];

        // The payer signs again after the change, so only the invoice
        // signature can catch it: the shown fields are what the node signed.
        yield 'a changed shown field' => [
            $proof->including(170)->with(170, Bolt12Builder::truncated(2000))->encode(),
            InvalidSignatureException::class,
            'invoice signature is not valid',
        ];

        yield 'swapped nonces' => [
            $proof->with(1004, self::swappedNonces($proof))->encode(),
            InvalidSignatureException::class,
            'invoice signature is not valid',
        ];

        yield 'a proof the payer did not sign' => [
            $proof->build(Bolt12Builder::ISSUER_SECRET)->encode('lnp'),
            InvalidSignatureException::class,
            'proof_signature is not valid',
        ];

        yield 'an invoice from a node that is not the issuer' => [
            PayerProofBuilder::forInvoice(
                Bolt12Builder::invoice()->with(176, (string) hex2bin(Bolt12Builder::publicKey(self::OTHER_NODE_SECRET))),
                nodeSecret: self::OTHER_NODE_SECRET,
            )->including(22)->encode(),
            InvalidFieldException::class,
            'invoice_node_id is not the offer_issuer_id',
        ];

        yield 'an invoice amount that differs from the request' => [
            PayerProofBuilder::forInvoice(Bolt12Builder::invoice()->withInt(170, 2000))->including(82, 170)->encode(),
            InvalidFieldException::class,
            'invoice_amount differs from invreq_amount',
        ];

        yield 'a note with a control character' => [$proof->withNote("a\x07b")->encode(), InvalidFieldException::class, 'proof_note is not valid UTF-8 text'];

        yield 'a shown description that is not text' => [
            PayerProofBuilder::forInvoice(Bolt12Builder::invoice()->with(10, "bad\xff"))->including(10)->encode(),
            InvalidFieldException::class,
            'offer_description is not valid UTF-8 text',
        ];

        yield 'a shown creation time past the year 9999' => [
            PayerProofBuilder::forInvoice(Bolt12Builder::invoice()->withInt(164, FieldReader::MAX_TIMESTAMP + 1))->including(164)->encode(),
            InvalidFieldException::class,
            'invoice_created_at is out of range',
        ];

        yield 'invoice features that are not minimally encoded' => [
            PayerProofBuilder::forInvoice(Bolt12Builder::invoice()->with(174, "\x00\x02"))->encode(),
            InvalidFieldException::class,
            'invoice_features is not minimally encoded',
        ];
    }

    /**
     * @return list<int>
     */
    private function markers(PayerProofBuilder $builder): array
    {
        $reader = new ByteReader($builder->proofRecords()[1002]);
        $markers = [];
        while (!$reader->isAtEnd()) {
            $markers[] = $reader->readBigSize();
        }

        return $markers;
    }

    private static function swappedNonces(PayerProofBuilder $builder): string
    {
        [$first, $second, $third] = str_split($builder->proofRecords()[1004], 32);

        return $second.$first.$third;
    }
}
