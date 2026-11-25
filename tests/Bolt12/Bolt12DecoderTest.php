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
use Jorijn\Bitcoin\Bolt11\Internal\Bech32;
use Jorijn\Bitcoin\Bolt11\Internal\Secp256k1;
use Jorijn\Bitcoin\Bolt11\Model\Network;
use Jorijn\Bitcoin\Bolt12\Bolt12Decoder;
use Jorijn\Bitcoin\Bolt12\Exception\Bolt12DecodeException;
use Jorijn\Bitcoin\Bolt12\Exception\InvalidEncodingException;
use Jorijn\Bitcoin\Bolt12\Exception\InvalidFieldException;
use Jorijn\Bitcoin\Bolt12\Exception\InvalidSignatureException;
use Jorijn\Bitcoin\Bolt12\Exception\MalformedTlvException;
use Jorijn\Bitcoin\Bolt12\Exception\UnknownRequiredFeatureException;
use Jorijn\Bitcoin\Bolt12\Exception\UnknownRequiredFieldException;
use Jorijn\Bitcoin\Bolt12\Internal\Bolt12String;
use Jorijn\Bitcoin\Bolt12\Internal\ByteReader;
use Jorijn\Bitcoin\Bolt12\Internal\MerkleTree;
use Jorijn\Bitcoin\Bolt12\Internal\TlvRecord;
use Jorijn\Bitcoin\Bolt12\Model\BlindedHop;
use Jorijn\Bitcoin\Bolt12\Model\BlindedPath;
use Jorijn\Bitcoin\Bolt12\Model\Chain;
use Jorijn\Bitcoin\Bolt12\Model\FallbackAddress;
use Jorijn\Bitcoin\Bolt12\Model\Features;
use Jorijn\Bitcoin\Bolt12\Model\Invoice;
use Jorijn\Bitcoin\Bolt12\Model\InvoiceRequest;
use Jorijn\Bitcoin\Bolt12\Model\Offer;
use Jorijn\Bitcoin\Bolt12\Model\PaymentPath;
use Jorijn\Bitcoin\Bolt12\Model\UnknownField;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Tests\Jorijn\Bitcoin\Bolt12\Support\Bolt12Builder;

/**
 * Every reader rule of the decoder, each tested with a message that is
 * valid except for the one thing under test (built with Bolt12Builder).
 *
 * @internal
 */
#[CoversClass(Bolt12Decoder::class)]
#[CoversClass(Offer::class)]
#[CoversClass(InvoiceRequest::class)]
#[CoversClass(Invoice::class)]
#[CoversClass(PaymentPath::class)]
#[CoversClass(FallbackAddress::class)]
#[CoversClass(UnknownField::class)]
#[CoversClass(BlindedHop::class)]
#[CoversClass(Bolt12DecodeException::class)]
#[CoversClass(UnknownRequiredFeatureException::class)]
#[CoversClass(UnknownRequiredFieldException::class)]
#[UsesClass(Bolt12String::class)]
#[UsesClass(ByteReader::class)]
#[UsesClass(TlvRecord::class)]
#[UsesClass(MerkleTree::class)]
#[UsesClass(Bech32::class)]
#[UsesClass(Secp256k1::class)]
#[UsesClass(BlindedPath::class)]
#[UsesClass(Features::class)]
#[UsesClass(Chain::class)]
#[UsesClass(Network::class)]
final class Bolt12DecoderTest extends TestCase
{
    private const OTHER_SECRET = '4343434343434343434343434343434343434343434343434343434343434343';

    private Bolt12Decoder $decoder;

    protected function setUp(): void
    {
        $this->decoder = new Bolt12Decoder();
    }

    // Offers

    public function testDecodesAMinimalOffer(): void
    {
        $offer = $this->decoder->decodeOffer(Bolt12Builder::offer()->encode('lno'));

        self::assertSame([Chain::BITCOIN], $offer->getChains());
        self::assertTrue($offer->isForChain(strtoupper(Chain::BITCOIN)));
        self::assertFalse($offer->isForChain(Chain::TESTNET3));
        self::assertSame('Test vectors', $offer->getDescription());
        self::assertSame(Bolt12Builder::ISSUER_ID, $offer->getIssuerId());
        self::assertNull($offer->getMetadata());
        self::assertNull($offer->getCurrency());
        self::assertNull($offer->getAmount());
        self::assertNull($offer->getMilliSatoshis());
        self::assertSame([], $offer->getFeatures()->getBits());
        self::assertNull($offer->getAbsoluteExpiry());
        self::assertFalse($offer->isExpired());
        self::assertSame([], $offer->getPaths());
        self::assertNull($offer->getIssuer());
        self::assertNull($offer->getQuantityMax());
        self::assertSame([], $offer->getUnknownFields());
    }

    public function testDecodesEveryOfferField(): void
    {
        $offer = $this->decoder->decodeOffer(
            Bolt12Builder::offer()
                ->with(2, (string) hex2bin(Chain::TESTNET4.Chain::SIGNET))
                ->with(4, "\x01\x02")
                ->with(6, 'EUR')
                ->withInt(8, 1250)
                ->with(12, "\x02\x00") // bit 9: an odd, optional feature
                ->withInt(14, 1_900_000_000)
                ->with(16, Bolt12Builder::blindedPath())
                ->with(18, 'example.com')
                ->withInt(20, 5)
                ->with(41, 'odd')
                ->encode('lno'),
        );

        self::assertSame([Chain::TESTNET4, Chain::SIGNET], $offer->getChains());
        self::assertSame('0102', $offer->getMetadata());
        self::assertSame('EUR', $offer->getCurrency());
        self::assertSame(1250, $offer->getAmount());
        self::assertNull($offer->getMilliSatoshis(), 'an amount in euro cents is not millisatoshis');
        self::assertSame([9], $offer->getFeatures()->getBits());
        self::assertSame('2030-03-17T17:46:40+00:00', $offer->getAbsoluteExpiry()?->format(\DateTimeInterface::ATOM));
        self::assertFalse($offer->isExpired(new \DateTimeImmutable('2030-03-17T17:46:40Z')));
        self::assertTrue($offer->isExpired(new \DateTimeImmutable('2030-03-17T17:46:41Z')));
        self::assertCount(1, $offer->getPaths());
        self::assertSame('example.com', $offer->getIssuer());
        self::assertSame(5, $offer->getQuantityMax());
        self::assertSame([['type' => 41, 'value' => '6f6464']], self::unknownFields($offer->getUnknownFields()));

        $array = $offer->toArray();
        self::assertSame(1250, $array['amount']);
        self::assertSame('2030-03-17T17:46:40+00:00', $array['absolute_expiry']);
        self::assertSame([['type' => 41, 'value' => '6f6464']], $array['unknown_fields']);
        self::assertSame(json_encode($array), json_encode($offer));
    }

    public function testAmountWithoutCurrencyIsInMilliSatoshis(): void
    {
        $offer = $this->decoder->decodeOffer(Bolt12Builder::offer()->withInt(8, 21_000)->encode('lno'));

        self::assertSame(21_000, $offer->getMilliSatoshis());
    }

    public function testDecodeChoosesTheTypeByPrefix(): void
    {
        self::assertInstanceOf(Offer::class, $this->decoder->decode(Bolt12Builder::offer()->encode('lno')));
        self::assertInstanceOf(InvoiceRequest::class, $this->decoder->decode(self::signedRequest()->encode('lnr')));
        self::assertInstanceOf(Invoice::class, $this->decoder->decode(self::signedInvoice()->encode('lni')));
    }

    public function testDecodeRejectsAnUnknownPrefix(): void
    {
        $this->expectException(InvalidEncodingException::class);
        $this->expectExceptionMessage('unknown BOLT #12 prefix "lnp"');

        $this->decoder->decode(Bolt12Builder::offer()->encode('lnp'));
    }

    public function testEachMethodWantsItsOwnPrefix(): void
    {
        $this->expectException(InvalidEncodingException::class);
        $this->expectExceptionMessage('expected prefix "lno", got "lnr"');

        $this->decoder->decodeOffer(self::signedRequest()->encode('lnr'));
    }

    /**
     * @param class-string<Bolt12DecodeException> $exception
     */
    #[DataProvider('provideRejectsInvalidOffersCases')]
    public function testRejectsInvalidOffers(Bolt12Builder $offer, string $exception, string $message): void
    {
        $this->expectException($exception);
        $this->expectExceptionMessage($message);

        $this->decoder->decodeOffer($offer->encode('lno'));
    }

    /**
     * Correctly encoded versions of what the malformed spec vectors aim at,
     * and the rules no spec vector covers.
     *
     * @return iterable<string, array{Bolt12Builder, class-string<Bolt12DecodeException>, string}>
     */
    public static function provideRejectsInvalidOffersCases(): iterable
    {
        $offer = Bolt12Builder::offer();

        yield 'blinded path without hops' => [$offer->with(16, Bolt12Builder::blindedPath(hops: 0)), InvalidFieldException::class, 'blinded path without hops'];

        yield 'bad first_node_id' => [$offer->with(16, Bolt12Builder::blindedPath('04'.str_repeat('02', 32))), InvalidFieldException::class, 'invalid first_node_id'];

        yield 'bad path key' => [$offer->with(16, substr_replace(Bolt12Builder::blindedPath('010000010000020003'), str_repeat("\x05", 33), 9, 33)), InvalidFieldException::class, 'invalid first_path_key'];

        yield 'empty offer_paths' => [$offer->with(16, ''), MalformedTlvException::class, 'offer_paths is malformed'];

        yield 'unknown even experimental type' => [$offer->with(1_000_000_002, 'x'), UnknownRequiredFieldException::class, 'unknown even TLV type 1000000002'];

        yield 'type above the experimental range' => [$offer->with(2_000_000_001, 'x'), InvalidFieldException::class, 'TLV type 2000000001 is outside'];

        yield 'type 0 is for invoice requests' => [$offer->with(0, 'x'), InvalidFieldException::class, 'TLV type 0 is outside'];

        yield 'type not minimally encoded' => [$offer->withRawRecord("\xFD\x00\x29\x00"), MalformedTlvException::class, 'not minimally encoded'];

        yield 'amount with a leading zero' => [$offer->with(8, "\x00\x01"), MalformedTlvException::class, 'offer_amount: truncated integer is not minimally encoded'];

        yield 'amount of nine bytes' => [$offer->with(8, str_repeat("\x01", 9)), MalformedTlvException::class, 'longer than 8 bytes'];

        yield 'amount beyond PHP_INT_MAX' => [$offer->with(8, str_repeat("\xFF", 8)), MalformedTlvException::class, 'does not fit'];

        yield 'features with a leading zero' => [$offer->with(12, "\x00\x02"), InvalidFieldException::class, 'offer_features is not minimally encoded'];

        yield 'features requiring bit 8' => [$offer->with(12, "\x01\x00"), UnknownRequiredFeatureException::class, 'unknown feature bits 8'];

        yield 'description with a control character' => [$offer->with(10, "pay\x07"), InvalidFieldException::class, 'offer_description is not valid UTF-8 text'];

        yield 'issuer with a line separator' => [$offer->with(18, "a\u{2028}b"), InvalidFieldException::class, 'offer_issuer is not valid UTF-8 text'];

        yield 'issuer id of 32 bytes' => [$offer->with(22, str_repeat("\x02", 32)), MalformedTlvException::class, 'offer_issuer_id must be 33 bytes'];

        yield 'expiry after the year 9999' => [$offer->withInt(14, 253_402_300_800), InvalidFieldException::class, 'offer_absolute_expiry is out of range'];

        yield 'truncated record' => [$offer->withRawRecord("\x29\x05ab"), MalformedTlvException::class, 'truncated'];
    }

    public function testAcceptsAShortChannelIdAsIntroductionNode(): void
    {
        // Direction 1, channel 1x2x3, then the path key and one hop.
        $path = Bolt12Builder::blindedPath('010000010000020003');
        $offer = $this->decoder->decodeOffer(Bolt12Builder::create()->with(10, 'x')->with(16, $path)->encode('lno'));

        $blindedPath = $offer->getPaths()[0];
        self::assertNull($offer->getIssuerId());
        self::assertSame('010000010000020003', $blindedPath->getIntroductionNode());
        self::assertNull($blindedPath->getIntroductionNodeId());
        self::assertSame('1x2x3', $blindedPath->getIntroductionShortChannelId());
        self::assertSame(1, $blindedPath->getIntroductionDirection());
        self::assertSame('abc', hex2bin($blindedPath->getHops()[0]->getEncryptedRecipientData()));
        self::assertSame(
            ['blinded_node_id' => '02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145', 'encrypted_recipient_data' => '616263'],
            $blindedPath->getHops()[0]->toArray(),
        );
    }

    public function testExceptionsShareTheBolt11Interface(): void
    {
        try {
            $this->decoder->decode('not an offer');
            self::fail('expected an exception');
        } catch (ExceptionInterface $exception) {
            self::assertInstanceOf(Bolt12DecodeException::class, $exception);
        }
    }

    public function testExceptionsCarryTheOffendingTypeAndBits(): void
    {
        try {
            $this->decoder->decodeOffer(Bolt12Builder::offer()->with(40, 'x')->encode('lno'));
            self::fail('expected an exception');
        } catch (UnknownRequiredFieldException $exception) {
            self::assertSame(40, $exception->getType());
        }

        try {
            $this->decoder->decodeOffer(Bolt12Builder::offer()->with(12, "\x05\x00")->encode('lno'));
            self::fail('expected an exception');
        } catch (UnknownRequiredFeatureException $exception) {
            self::assertSame([8, 10], $exception->getFeatureBits());
        }
    }

    // Invoice requests

    public function testDecodesAnInvoiceRequestForAnOffer(): void
    {
        $request = $this->decoder->decodeInvoiceRequest(
            Bolt12Builder::invoiceRequest()
                ->with(89, 'thanks!')
                ->with(91, "\x05alice\x0bexample.com")
                ->with(85, 'odd')
                ->sign('invoice_request', Bolt12Builder::PAYER_SECRET)
                ->encode('lnr'),
        );

        self::assertTrue($request->isForOffer());
        self::assertSame('Test vectors', $request->getOffer()->getDescription());
        self::assertSame(str_repeat('07', 16), $request->getMetadata());
        self::assertSame(Chain::BITCOIN, $request->getChain());
        self::assertSame(1000, $request->getAmount());
        self::assertSame([], $request->getFeatures()->getBits());
        self::assertNull($request->getQuantity());
        self::assertSame(Bolt12Builder::PAYER_ID, $request->getPayerId());
        self::assertSame('thanks!', $request->getPayerNote());
        self::assertSame([], $request->getPaths());
        self::assertSame('alice@example.com', $request->getBip353Name());
        self::assertSame(128, \strlen((string) $request->getSignature()));
        self::assertSame([['type' => 85, 'value' => '6f6464']], self::unknownFields($request->getUnknownFields()));

        $array = $request->toArray();
        self::assertSame(Bolt12Builder::PAYER_ID, $array['payer_id']);
        self::assertSame('Test vectors', $array['offer']['description']);
        self::assertSame(json_encode($array), json_encode($request));
    }

    public function testRejectsATamperedInvoiceRequest(): void
    {
        $signed = self::signedRequest();
        // Raise the amount after signing: the signature no longer matches.
        $tampered = $signed->withInt(82, 2000);

        $this->expectException(InvalidSignatureException::class);
        $this->expectExceptionMessage('invoice_request signature is not valid');

        $this->decoder->decodeInvoiceRequest($tampered->encode('lnr'));
    }

    public function testRejectsAnInvoiceRequestSignedByAnotherKey(): void
    {
        $this->expectException(InvalidSignatureException::class);

        $this->decoder->decodeInvoiceRequest(Bolt12Builder::invoiceRequest()->sign('invoice_request', self::OTHER_SECRET)->encode('lnr'));
    }

    public function testRejectsASignatureForAnotherMessageType(): void
    {
        // Same key, same merkle root, but the tag says "invoice": a signature
        // over one kind of message must not pass as another.
        $this->expectException(InvalidSignatureException::class);

        $this->decoder->decodeInvoiceRequest(Bolt12Builder::invoiceRequest()->sign('invoice', Bolt12Builder::PAYER_SECRET)->encode('lnr'));
    }

    public function testUnknownOddSignatureRecordsAreNotSigned(): void
    {
        // Types 240 to 1000 are signatures: they stay out of the merkle tree,
        // so one added after signing does not break the signature.
        $request = $this->decoder->decodeInvoiceRequest(self::signedRequest()->with(241, 'another signature')->encode('lnr'));

        self::assertSame([['type' => 241, 'value' => bin2hex('another signature')]], self::unknownFields($request->getUnknownFields()));
    }

    /**
     * @param class-string<Bolt12DecodeException> $exception
     */
    #[DataProvider('provideRejectsInvalidInvoiceRequestsCases')]
    public function testRejectsInvalidInvoiceRequests(Bolt12Builder $request, string $exception, string $message): void
    {
        $this->expectException($exception);
        $this->expectExceptionMessage($message);

        $this->decoder->decodeInvoiceRequest($request->sign('invoice_request', Bolt12Builder::PAYER_SECRET)->encode('lnr'));
    }

    /**
     * @return iterable<string, array{Bolt12Builder, class-string<Bolt12DecodeException>, string}>
     */
    public static function provideRejectsInvalidInvoiceRequestsCases(): iterable
    {
        $request = Bolt12Builder::invoiceRequest();
        $limited = $request->withInt(20, 3);

        yield 'no invreq_metadata' => [$request->without(0), InvalidFieldException::class, 'invoice request has no invreq_metadata'];

        yield 'no invreq_payer_id' => [$request->without(88), InvalidFieldException::class, 'invoice request has no invreq_payer_id'];

        yield 'type in the invoice range' => [$request->with(161, 'x'), InvalidFieldException::class, 'TLV type 161 is outside'];

        yield 'unknown even request type' => [$request->with(100, 'x'), UnknownRequiredFieldException::class, 'unknown even TLV type 100'];

        yield 'invreq_features requiring bit 0' => [$request->with(84, "\x01"), UnknownRequiredFeatureException::class, 'invreq_features requires unknown feature bits 0'];

        yield 'quantity without quantity_max' => [$request->withInt(86, 1), InvalidFieldException::class, 'has invreq_quantity but the offer has no offer_quantity_max'];

        yield 'quantity_max without quantity' => [$limited, InvalidFieldException::class, 'invreq_quantity is missing'];

        yield 'quantity of zero' => [$limited->with(86, ''), InvalidFieldException::class, 'invreq_quantity is missing, zero'];

        yield 'quantity above quantity_max' => [$limited->withInt(86, 4), InvalidFieldException::class, 'above offer_quantity_max'];

        yield 'offer without amount and request without amount' => [$request->without(82), InvalidFieldException::class, 'has no invreq_amount for an offer without offer_amount'];

        yield 'amount below the offer amount' => [$request->withInt(8, 1001), InvalidFieldException::class, 'invreq_amount is less than the offer asks'];

        yield 'amount below the offer amount times quantity' => [$request->withInt(8, 400)->withInt(20, 0)->withInt(86, 3), InvalidFieldException::class, 'invreq_amount is less than the offer asks'];

        yield 'offer amount times quantity overflows' => [$request->withInt(8, PHP_INT_MAX)->withInt(20, 0)->withInt(86, 2), InvalidFieldException::class, 'invreq_amount is less than the offer asks'];

        yield 'chain the offer is not for' => [$request->with(80, (string) hex2bin(Chain::TESTNET3)), InvalidFieldException::class, 'chain the offer is not for'];

        yield 'bitcoin implied but the offer lists only testnet' => [$request->with(2, (string) hex2bin(Chain::TESTNET3)), InvalidFieldException::class, 'chain the offer is not for'];

        yield 'invreq_chain of 31 bytes' => [$request->with(80, str_repeat("\x01", 31)), MalformedTlvException::class, 'invreq_chain must be 32 bytes'];

        yield 'zero offer amount' => [$request->with(8, ''), InvalidFieldException::class, 'offer_amount must be greater than zero'];

        yield 'payer note with a control character' => [$request->with(89, "\x1b[31m"), InvalidFieldException::class, 'invreq_payer_note is not valid UTF-8 text'];

        yield 'BIP 353 name with a space' => [$request->with(91, "\x05al ce\x0bexample.com"), InvalidFieldException::class, 'characters BIP 353 does not allow'];

        yield 'BIP 353 name truncated' => [$request->with(91, "\x05alice\x0bexample"), MalformedTlvException::class, 'invreq_bip_353_name is malformed'];

        yield 'BIP 353 name with trailing bytes' => [$request->with(91, "\x01a\x01bc"), MalformedTlvException::class, 'trailing bytes'];

        yield 'invreq_paths without hops' => [$request->with(90, Bolt12Builder::blindedPath(hops: 0)), InvalidFieldException::class, 'invreq_paths has a blinded path without hops'];

        yield 'payer id not on the curve' => [$request->with(88, "\x02".str_repeat("\xFF", 32)), InvalidFieldException::class, 'invreq_payer_id is not a valid public key'];
    }

    public function testAcceptsQuantitiesWithinTheOffer(): void
    {
        $request = Bolt12Builder::invoiceRequest()->withInt(8, 300)->withInt(82, 900);

        // quantity_max 0 means no limit.
        $unlimited = $this->decoder->decodeInvoiceRequest($request->withInt(20, 0)->withInt(86, 3)->sign('invoice_request', Bolt12Builder::PAYER_SECRET)->encode('lnr'));
        self::assertSame(3, $unlimited->getQuantity());
        self::assertSame(0, $unlimited->getOffer()->getQuantityMax());

        $limited = $this->decoder->decodeInvoiceRequest($request->withInt(20, 3)->withInt(86, 3)->sign('invoice_request', Bolt12Builder::PAYER_SECRET)->encode('lnr'));
        self::assertSame(3, $limited->getQuantity());
    }

    public function testDoesNotCompareAmountsInAnotherCurrency(): void
    {
        // 50 euro cents cannot be compared to 1000 msat without an exchange
        // rate: that is the issuer's call, not the decoder's.
        $request = $this->decoder->decodeInvoiceRequest(
            Bolt12Builder::invoiceRequest()->with(6, 'EUR')->withInt(8, 50)->sign('invoice_request', Bolt12Builder::PAYER_SECRET)->encode('lnr'),
        );

        self::assertSame(1000, $request->getAmount());
    }

    public function testAcceptsTheChainTheOfferNames(): void
    {
        $request = $this->decoder->decodeInvoiceRequest(
            Bolt12Builder::invoiceRequest()
                ->with(2, (string) hex2bin(Chain::BITCOIN.Chain::TESTNET3))
                ->with(80, (string) hex2bin(Chain::TESTNET3))
                ->sign('invoice_request', Bolt12Builder::PAYER_SECRET)
                ->encode('lnr'),
        );

        self::assertSame(Chain::TESTNET3, $request->getChain());
    }

    public function testRequiresASignatureForAnOffer(): void
    {
        $this->expectException(InvalidSignatureException::class);
        $this->expectExceptionMessage('invoice request for an offer has no signature');

        $this->decoder->decodeInvoiceRequest(Bolt12Builder::invoiceRequest()->encode('lnr'));
    }

    public function testDecodesAnUnsignedRequestWithoutAnOffer(): void
    {
        // A refund: the sender offers to pay 5000 msat and publishes this as
        // a QR code. The specification tells that writer not to sign it.
        $refund = Bolt12Builder::invoiceRequest()->without(22)->withInt(82, 5000)->with(90, Bolt12Builder::blindedPath());
        $request = $this->decoder->decodeInvoiceRequest($refund->encode('lnr'));

        self::assertFalse($request->isForOffer());
        self::assertNull($request->getSignature());
        self::assertSame(5000, $request->getAmount());
        self::assertCount(1, $request->getPaths());

        // Signed anyway, the signature must still be right.
        self::assertNotNull($this->decoder->decodeInvoiceRequest($refund->sign('invoice_request', Bolt12Builder::PAYER_SECRET)->encode('lnr'))->getSignature());
    }

    /**
     * @param class-string<Bolt12DecodeException> $exception
     */
    #[DataProvider('provideRejectsInvalidRequestsWithoutAnOfferCases')]
    public function testRejectsInvalidRequestsWithoutAnOffer(Bolt12Builder $request, string $exception, string $message): void
    {
        $this->expectException($exception);
        $this->expectExceptionMessage($message);

        $this->decoder->decodeInvoiceRequest($request->encode('lnr'));
    }

    /**
     * @return iterable<string, array{Bolt12Builder, class-string<Bolt12DecodeException>, string}>
     */
    public static function provideRejectsInvalidRequestsWithoutAnOfferCases(): iterable
    {
        $refund = Bolt12Builder::invoiceRequest()->without(22);

        yield 'no amount' => [$refund->without(82), InvalidFieldException::class, 'without an offer has no invreq_amount'];

        yield 'offer_chains' => [$refund->with(2, (string) hex2bin(Chain::BITCOIN)), InvalidFieldException::class, 'without an offer has offer_chains'];

        yield 'offer_features' => [$refund->with(12, "\x02"), InvalidFieldException::class, 'without an offer has offer_features'];

        yield 'offer_quantity_max' => [$refund->withInt(20, 2), InvalidFieldException::class, 'without an offer has offer_quantity_max'];

        yield 'wrong signature' => [$refund->sign('invoice_request', self::OTHER_SECRET), InvalidSignatureException::class, 'signature is not valid'];

        yield 'signature of 63 bytes' => [$refund->with(240, str_repeat("\x01", 63)), MalformedTlvException::class, 'signature must be 64 bytes'];
    }

    // Invoices

    public function testDecodesAnInvoice(): void
    {
        $invoice = $this->decoder->decodeInvoice(
            Bolt12Builder::invoice()
                ->withInt(166, 600)
                ->with(172, "\x00\x00\x14".str_repeat("\x75", 20)."\x01\x00\x20".str_repeat("\x11", 32))
                ->with(174, "\x02\x00\x00") // bit 17: multi-part payments allowed
                ->with(181, 'odd')
                ->sign('invoice', Bolt12Builder::ISSUER_SECRET)
                ->encode('lni'),
        );

        self::assertSame(Bolt12Builder::PAYER_ID, $invoice->getInvoiceRequest()->getPayerId());
        self::assertNull($invoice->getInvoiceRequest()->getSignature(), 'the request is not signed on its own inside an invoice');
        self::assertSame('Test vectors', $invoice->getOffer()->getDescription());
        self::assertSame(Chain::BITCOIN, $invoice->getChain());
        self::assertSame(1000, $invoice->getAmount());
        self::assertSame(1, $invoice->getSatoshis());
        self::assertSame(Bolt12Builder::PAYMENT_HASH, $invoice->getPaymentHash());
        self::assertSame(Bolt12Builder::ISSUER_ID, $invoice->getNodeId());
        self::assertSame(128, \strlen($invoice->getSignature()));
        self::assertSame('2023-11-14T22:13:20+00:00', $invoice->getCreatedAt()->format(\DateTimeInterface::ATOM));
        self::assertSame(600, $invoice->getRelativeExpiry());
        self::assertSame('2023-11-14T22:23:20+00:00', $invoice->getExpiresAt()->format(\DateTimeInterface::ATOM));
        self::assertTrue($invoice->isExpired());
        self::assertFalse($invoice->isExpired(new \DateTimeImmutable('2023-11-14T22:23:20Z')));
        self::assertTrue($invoice->getFeatures()->supports(Features::MPP));
        self::assertFalse($invoice->getFeatures()->requires(Features::MPP));
        self::assertSame([['type' => 181, 'value' => '6f6464']], self::unknownFields($invoice->getUnknownFields()));

        $path = $invoice->getPaths()[0];
        self::assertSame(1000, $path->getFeeBaseMsat());
        self::assertSame(100, $path->getFeeProportionalMillionths());
        self::assertSame(144, $path->getCltvExpiryDelta());
        self::assertSame(1, $path->getHtlcMinimumMsat());
        self::assertSame(2_000_000_000, $path->getHtlcMaximumMsat());
        self::assertSame([], $path->getFeatures()->getBits());
        self::assertTrue($path->isUsable());

        // Expected addresses computed separately with the BIP-350 reference encoder.
        self::assertSame([
            ['version' => 0, 'program' => str_repeat('75', 20), 'address' => 'bc1qw46h2at4w46h2at4w46h2at4w46h2at42z30yf'],
            ['version' => 1, 'program' => str_repeat('11', 32), 'address' => 'bc1pzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs64v5e4'],
        ], array_map(static fn (FallbackAddress $address): array => $address->toArray(), $invoice->getFallbackAddresses()));

        $array = $invoice->toArray();
        self::assertSame('2023-11-14T22:23:20+00:00', $array['expires_at']);
        self::assertSame(0, $array['fallback_addresses'][0]['version']);
        self::assertSame(1000, $array['paths'][0]['fee_base_msat']);
        self::assertSame(json_encode($array), json_encode($invoice));
    }

    public function testDefaultsToTwoHoursOfExpiry(): void
    {
        $invoice = $this->decoder->decodeInvoice(self::signedInvoice()->encode('lni'));

        self::assertSame(7200, $invoice->getRelativeExpiry());
        self::assertSame(Bolt12Builder::CREATED_AT + 7200, $invoice->getExpiresAt()->getTimestamp());
    }

    public function testFallbackAddressesFollowTheChain(): void
    {
        $invoice = $this->decoder->decodeInvoice(
            Bolt12Builder::invoice()
                ->with(2, (string) hex2bin(Chain::REGTEST.'1466275836220db2944ca059a3a10ef6fd2ea684b0688d2c379296888a206003'))
                ->with(80, (string) hex2bin(Chain::REGTEST))
                ->with(172, "\x00\x00\x14".str_repeat("\x75", 20))
                ->sign('invoice', Bolt12Builder::ISSUER_SECRET)
                ->encode('lni'),
        );
        self::assertSame('bcrt1qw46h2at4w46h2at4w46h2at4w46h2at4zdn3gn', $invoice->getFallbackAddresses()[0]->getAddress());

        // Liquid has no segwit prefix this library knows: keep the program, no address.
        $liquid = '1466275836220db2944ca059a3a10ef6fd2ea684b0688d2c379296888a206003';
        $invoice = $this->decoder->decodeInvoice(
            Bolt12Builder::invoice()
                ->with(2, (string) hex2bin($liquid))
                ->with(80, (string) hex2bin($liquid))
                ->with(172, "\x00\x00\x14".str_repeat("\x75", 20))
                ->sign('invoice', Bolt12Builder::ISSUER_SECRET)
                ->encode('lni'),
        );
        $address = $invoice->getFallbackAddresses()[0];
        self::assertNull($address->getAddress());
        self::assertSame(0, $address->getVersion());
        self::assertSame(str_repeat('75', 20), $address->getProgram());
    }

    public function testIgnoresFallbackAddressesItCannotUse(): void
    {
        $invoice = $this->decoder->decodeInvoice(
            Bolt12Builder::invoice()
                ->with(172, implode('', [
                    "\x11\x00\x14".str_repeat("\x01", 20), // version 17
                    "\x01\x00\x01\x01",                    // 1-byte program
                    "\x01\x00\x29".str_repeat("\x01", 41), // 41-byte program
                    "\x00\x00\x15".str_repeat("\x01", 21), // version 0 with 21 bytes
                    "\x02\x00\x02\x01\x02",                // usable
                ]))
                ->sign('invoice', Bolt12Builder::ISSUER_SECRET)
                ->encode('lni'),
        );

        self::assertCount(1, $invoice->getFallbackAddresses());
        self::assertSame(2, $invoice->getFallbackAddresses()[0]->getVersion());
    }

    public function testCapsAnHtlcMaximumBeyondPhpIntMax(): void
    {
        $payInfo = pack('NNnJ', 1000, 100, 144, 1).str_repeat("\xFF", 8)."\x00\x00";
        $invoice = $this->decoder->decodeInvoice(Bolt12Builder::invoice()->with(162, $payInfo)->sign('invoice', Bolt12Builder::ISSUER_SECRET)->encode('lni'));

        self::assertSame(PHP_INT_MAX, $invoice->getPaths()[0]->getHtlcMaximumMsat());
    }

    public function testKeepsPathsWithUnknownRequiredFeaturesWhileOneIsUsable(): void
    {
        $invoice = $this->decoder->decodeInvoice(
            Bolt12Builder::invoice()
                ->with(160, Bolt12Builder::blindedPath().Bolt12Builder::blindedPath())
                ->with(162, Bolt12Builder::payInfo("\x01").Bolt12Builder::payInfo())
                ->sign('invoice', Bolt12Builder::ISSUER_SECRET)
                ->encode('lni'),
        );

        self::assertFalse($invoice->getPaths()[0]->isUsable());
        self::assertSame([0], $invoice->getPaths()[0]->getFeatures()->getBits());
        self::assertTrue($invoice->getPaths()[1]->isUsable());
    }

    public function testAcceptsAnInvoiceForAnOfferWithOnlyPaths(): void
    {
        // Without offer_issuer_id the node id is the final blinded node id of
        // the path the request went through, which only the payer knows: the
        // decoder can only check the signature against the node id.
        $other = Bolt12Builder::publicKey(self::OTHER_SECRET);
        $invoice = $this->decoder->decodeInvoice(
            Bolt12Builder::invoice()
                ->without(22)
                ->with(16, Bolt12Builder::blindedPath())
                ->with(176, (string) hex2bin($other))
                ->sign('invoice', self::OTHER_SECRET)
                ->encode('lni'),
        );

        self::assertSame($other, $invoice->getNodeId());
    }

    /**
     * @param class-string<Bolt12DecodeException> $exception
     */
    #[DataProvider('provideRejectsInvalidInvoicesCases')]
    public function testRejectsInvalidInvoices(Bolt12Builder $invoice, string $exception, string $message): void
    {
        $this->expectException($exception);
        $this->expectExceptionMessage($message);

        $this->decoder->decodeInvoice($invoice->sign('invoice', Bolt12Builder::ISSUER_SECRET)->encode('lni'));
    }

    /**
     * @return iterable<string, array{Bolt12Builder, class-string<Bolt12DecodeException>, string}>
     */
    public static function provideRejectsInvalidInvoicesCases(): iterable
    {
        $invoice = Bolt12Builder::invoice();

        yield 'no amount' => [$invoice->without(170), InvalidFieldException::class, 'invoice has no invoice_amount'];

        yield 'no created_at' => [$invoice->without(164), InvalidFieldException::class, 'invoice has no invoice_created_at'];

        yield 'no payment hash' => [$invoice->without(168), InvalidFieldException::class, 'invoice has no invoice_payment_hash'];

        yield 'no node id' => [$invoice->without(176), InvalidFieldException::class, 'invoice has no invoice_node_id'];

        yield 'no paths' => [$invoice->without(160), InvalidFieldException::class, 'invoice has no invoice_paths'];

        yield 'no blindedpay' => [$invoice->without(162), InvalidFieldException::class, 'invoice has no invoice_blindedpay'];

        yield 'fewer payinfo than paths' => [$invoice->with(160, Bolt12Builder::blindedPath().Bolt12Builder::blindedPath()), InvalidFieldException::class, 'one entry per invoice_paths entry'];

        yield 'more payinfo than paths' => [$invoice->with(162, Bolt12Builder::payInfo().Bolt12Builder::payInfo()), InvalidFieldException::class, 'more entries than invoice_paths'];

        yield 'truncated payinfo' => [$invoice->with(162, substr(Bolt12Builder::payInfo(), 0, 20)), MalformedTlvException::class, 'invoice_blindedpay is malformed'];

        yield 'no usable path' => [$invoice->with(162, Bolt12Builder::payInfo("\x01")), InvalidFieldException::class, 'no blinded path without unknown required features'];

        yield 'path without hops' => [$invoice->with(160, Bolt12Builder::blindedPath(hops: 0)), InvalidFieldException::class, 'invoice_paths has a blinded path without hops'];

        yield 'amount differs from the request' => [$invoice->withInt(170, 999), InvalidFieldException::class, 'invoice_amount differs from invreq_amount'];

        yield 'node id is not the issuer id' => [$invoice->with(176, (string) hex2bin(Bolt12Builder::PAYER_ID)), InvalidFieldException::class, 'invoice_node_id is not the offer_issuer_id'];

        yield 'invoice features requiring bit 18' => [$invoice->with(174, "\x04\x00\x00"), UnknownRequiredFeatureException::class, 'invoice_features requires unknown feature bits 18'];

        yield 'expiry after the year 9999' => [$invoice->withInt(164, 253_402_300_000)->withInt(166, 800), InvalidFieldException::class, 'invoice expiry is out of range'];

        yield 'relative expiry of five bytes' => [$invoice->with(166, "\x01\x00\x00\x00\x00"), MalformedTlvException::class, 'longer than 4 bytes'];

        yield 'payment hash of 31 bytes' => [$invoice->with(168, str_repeat("\x01", 31)), MalformedTlvException::class, 'invoice_payment_hash must be 32 bytes'];

        yield 'truncated fallback' => [$invoice->with(172, "\x00\x00\x14\x01"), MalformedTlvException::class, 'invoice_fallbacks is malformed'];

        yield 'type above the invoice ranges' => [$invoice->with(4_000_000_001, 'x'), InvalidFieldException::class, 'TLV type 4000000001 is outside'];

        yield 'no payer id' => [$invoice->without(88), InvalidFieldException::class, 'invoice request has no invreq_payer_id'];
    }

    public function testRejectsATamperedInvoice(): void
    {
        $this->expectException(InvalidSignatureException::class);
        $this->expectExceptionMessage('invoice signature is not valid');

        $this->decoder->decodeInvoice(self::signedInvoice()->with(168, str_repeat("\x02", 32))->encode('lni'));
    }

    public function testRequiresAnInvoiceSignature(): void
    {
        $this->expectException(InvalidSignatureException::class);
        $this->expectExceptionMessage('invoice has no signature');

        $this->decoder->decodeInvoice(Bolt12Builder::invoice()->encode('lni'));
    }

    /**
     * @param list<UnknownField> $fields
     *
     * @return list<array{type: int, value: string}>
     */
    private static function unknownFields(array $fields): array
    {
        return array_map(static fn (UnknownField $field): array => $field->toArray(), $fields);
    }

    private static function signedRequest(): Bolt12Builder
    {
        return Bolt12Builder::invoiceRequest()->sign('invoice_request', Bolt12Builder::PAYER_SECRET);
    }

    private static function signedInvoice(): Bolt12Builder
    {
        return Bolt12Builder::invoice()->sign('invoice', Bolt12Builder::ISSUER_SECRET);
    }
}
