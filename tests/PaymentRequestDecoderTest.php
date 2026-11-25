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

namespace Tests\Jorijn\Bitcoin\Bolt11;

use Jorijn\Bitcoin\Bolt11\Exception\InvalidAmountException;
use Jorijn\Bitcoin\Bolt11\Exception\InvalidPaymentRequestException;
use Jorijn\Bitcoin\Bolt11\Exception\PaymentRequestDecodeException;
use Jorijn\Bitcoin\Bolt11\Exception\SignatureDoesNotMatchPayeePubkeyDecodeException;
use Jorijn\Bitcoin\Bolt11\Exception\SignatureIncorrectOrMissingException;
use Jorijn\Bitcoin\Bolt11\Exception\UnableToDecodeBech32Exception;
use Jorijn\Bitcoin\Bolt11\Exception\UnknownNetworkVersionException;
use Jorijn\Bitcoin\Bolt11\Exception\UnknownRequiredFeatureException;
use Jorijn\Bitcoin\Bolt11\Exception\UnrecoverableSignatureException;
use Jorijn\Bitcoin\Bolt11\Internal\Base58;
use Jorijn\Bitcoin\Bolt11\Internal\Bech32;
use Jorijn\Bitcoin\Bolt11\Internal\Secp256k1;
use Jorijn\Bitcoin\Bolt11\Model\FallbackAddress;
use Jorijn\Bitcoin\Bolt11\Model\Features;
use Jorijn\Bitcoin\Bolt11\Model\Network;
use Jorijn\Bitcoin\Bolt11\Model\PaymentRequest;
use Jorijn\Bitcoin\Bolt11\Model\RouteHint;
use Jorijn\Bitcoin\Bolt11\Model\RouteHintHop;
use Jorijn\Bitcoin\Bolt11\Model\UnknownField;
use Jorijn\Bitcoin\Bolt11\PaymentRequestDecoder;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Tests\Jorijn\Bitcoin\Bolt11\Support\InvoiceBuilder;

/**
 * Every rule of the decoder, each tested with an invoice that is valid except
 * for the one thing under test (see InvoiceBuilder).
 *
 * @internal
 */
#[CoversClass(PaymentRequestDecoder::class)]
#[CoversClass(UnknownRequiredFeatureException::class)]
#[UsesClass(Bech32::class)]
#[UsesClass(Base58::class)]
#[UsesClass(Secp256k1::class)]
#[UsesClass(PaymentRequest::class)]
#[UsesClass(Network::class)]
#[UsesClass(Features::class)]
#[UsesClass(FallbackAddress::class)]
#[UsesClass(RouteHint::class)]
#[UsesClass(RouteHintHop::class)]
#[UsesClass(UnknownField::class)]
final class PaymentRequestDecoderTest extends TestCase
{
    private const OTHER_PUBLIC_KEY = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';

    /** One route hint hop: pubkey, short channel id, fee base 1000, 2500 ppm, cltv delta 40. */
    private const HOP = '03d06758583bb5154774a6eb221b1276c9e82d65bbaceca806d90e20c108f4b1c708fe4e000cf00001000003e8000009c40028';

    public function testDecodesEveryField(): void
    {
        $invoice = InvoiceBuilder::create('lnbc2500u')
            ->withBytesField(1, self::bin(InvoiceBuilder::PAYMENT_HASH))
            ->withBytesField(16, self::bin(InvoiceBuilder::PAYMENT_SECRET))
            ->withBytesField(13, 'a cup of coffee')
            ->withIntField(6, 7200)
            ->withIntField(24, 40)
            ->withBytesField(27, "\x01\xfa\xfa\xf0")
            // Bits 8, 14 and 17 (var_onion_optin, payment_secret, basic_mpp optional).
            ->withField(5, [0b00100, 0b10000, 0b01000, 0])
            ->withBytesField(19, self::bin(InvoiceBuilder::PUBLIC_KEY))
            ->withField(9, array_merge([0], InvoiceBuilder::bytesToWords(self::bin('751e76e8199196d454941c45d1b3a323f1433bd6'))))
            ->withBytesField(3, self::bin(self::HOP.self::HOP))
            ->withField(7, [1, 2, 3])
            ->build()
        ;

        $paymentRequest = (new PaymentRequestDecoder())->decode($invoice);

        self::assertSame('lnbc2500u', $paymentRequest->getPrefix());
        self::assertSame(Network::Mainnet, $paymentRequest->getNetwork());
        self::assertSame(250_000_000, $paymentRequest->getMilliSatoshis());
        self::assertSame(250_000, $paymentRequest->getSatoshis());
        self::assertSame(InvoiceBuilder::TIMESTAMP, $paymentRequest->getTimestamp()->getTimestamp());
        self::assertSame('+00:00', $paymentRequest->getTimestamp()->getTimezone()->getName());
        self::assertSame(InvoiceBuilder::PUBLIC_KEY, $paymentRequest->getPayeeNodeKey());
        self::assertSame(InvoiceBuilder::PAYMENT_HASH, $paymentRequest->getPaymentHash());
        self::assertSame(InvoiceBuilder::PAYMENT_SECRET, $paymentRequest->getPaymentSecret());
        self::assertSame('a cup of coffee', $paymentRequest->getDescription());
        self::assertNull($paymentRequest->getDescriptionHash());
        self::assertSame(7200, $paymentRequest->getExpiry());
        self::assertSame(InvoiceBuilder::TIMESTAMP + 7200, $paymentRequest->getExpiresAt()->getTimestamp());
        self::assertSame(40, $paymentRequest->getMinFinalCltvExpiryDelta());
        self::assertSame('01fafaf0', $paymentRequest->getMetadata());
        self::assertSame([8, 14, 17], $paymentRequest->getFeatures()->getBits());
        self::assertSame('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', $paymentRequest->getFallbackAddresses()[0]->getAddress());
        self::assertCount(1, $paymentRequest->getRouteHints());
        self::assertCount(2, $paymentRequest->getRouteHints()[0]->getHops());

        $hop = $paymentRequest->getRouteHints()[0]->getHops()[0];
        self::assertSame('03d06758583bb5154774a6eb221b1276c9e82d65bbaceca806d90e20c108f4b1c7', $hop->getPublicKey());
        self::assertSame('08fe4e000cf00001', $hop->getShortChannelId());
        self::assertSame(1000, $hop->getFeeBaseMsat());
        self::assertSame(2500, $hop->getFeeProportionalMillionths());
        self::assertSame(40, $hop->getCltvExpiryDelta());

        self::assertCount(1, $paymentRequest->getUnknownFields());
        self::assertSame(7, $paymentRequest->getUnknownFields()[0]->getType());
        self::assertSame([1, 2, 3], $paymentRequest->getUnknownFields()[0]->getWords());
    }

    public function testDefaultsForOptionalFields(): void
    {
        $paymentRequest = (new PaymentRequestDecoder())->decode(InvoiceBuilder::valid()->build());

        self::assertNull($paymentRequest->getMilliSatoshis());
        self::assertNull($paymentRequest->getSatoshis());
        self::assertSame(3600, $paymentRequest->getExpiry());
        self::assertSame(18, $paymentRequest->getMinFinalCltvExpiryDelta());
        self::assertNull($paymentRequest->getMetadata());
        self::assertSame([], $paymentRequest->getFeatures()->getBits());
        self::assertSame([], $paymentRequest->getFallbackAddresses());
        self::assertSame([], $paymentRequest->getRouteHints());
        self::assertSame([], $paymentRequest->getUnknownFields());
    }

    public function testDecodesUpperCase(): void
    {
        $paymentRequest = (new PaymentRequestDecoder())->decode(strtoupper(InvoiceBuilder::valid('lnbc20m')->build()));

        self::assertSame('lnbc20m', $paymentRequest->getPrefix());
        self::assertSame(InvoiceBuilder::PUBLIC_KEY, $paymentRequest->getPayeeNodeKey());
    }

    /**
     * Signet shares its address prefix with testnet, but is its own network.
     */
    #[DataProvider('provideNetworksCases')]
    public function testNetworks(string $humanReadablePart, Network $network, int $version, string $program, string $address): void
    {
        $invoice = InvoiceBuilder::valid($humanReadablePart)
            ->withField(9, array_merge([$version], InvoiceBuilder::bytesToWords(self::bin($program))))
            ->build()
        ;

        $paymentRequest = (new PaymentRequestDecoder())->decode($invoice);

        self::assertSame($network, $paymentRequest->getNetwork());
        self::assertSame($address, $paymentRequest->getFallbackAddresses()[0]->getAddress());
    }

    /**
     * @return iterable<string, array{string, Network, int, string, string}>
     */
    public static function provideNetworksCases(): iterable
    {
        $hash = '751e76e8199196d454941c45d1b3a323f1433bd6';

        yield 'mainnet P2PKH' => ['lnbc', Network::Mainnet, 17, $hash, '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH'];

        yield 'mainnet P2SH' => ['lnbc', Network::Mainnet, 18, $hash, '3CNHUhP3uyB9EUtRLsmvFUmvGdjGdkTxJw'];

        yield 'testnet P2WPKH' => ['lntb10u', Network::Testnet, 0, $hash, 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx'];

        yield 'signet P2WPKH' => ['lntbs10u', Network::Signet, 0, $hash, 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx'];

        yield 'signet P2PKH' => ['lntbs', Network::Signet, 17, $hash, 'mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r'];

        yield 'regtest P2WPKH' => ['lnbcrt10u', Network::Regtest, 0, $hash, 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080'];

        yield 'regtest P2SH' => ['lnbcrt', Network::Regtest, 18, $hash, '2N3vVYSK5XRgVSGWy21PnsRmBUywSQNdCsf'];

        yield 'mainnet P2TR' => ['lnbc', Network::Mainnet, 1, '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0'];
    }

    #[DataProvider('provideAmountsCases')]
    public function testAmounts(string $amount, int $milliSatoshis, int $satoshis): void
    {
        $paymentRequest = (new PaymentRequestDecoder())->decode(InvoiceBuilder::valid('lnbc'.$amount)->build());

        self::assertSame($milliSatoshis, $paymentRequest->getMilliSatoshis());
        self::assertSame($satoshis, $paymentRequest->getSatoshis());
    }

    /**
     * @return iterable<string, array{string, int, int}>
     */
    public static function provideAmountsCases(): iterable
    {
        yield 'whole bitcoin' => ['1', 100_000_000_000, 100_000_000];

        yield 'milli' => ['20m', 2_000_000_000, 2_000_000];

        yield 'micro' => ['2500u', 250_000_000, 250_000];

        yield 'nano' => ['1n', 100, 0];

        yield 'pico, one millisatoshi' => ['10p', 1, 0];

        yield 'pico, rounds down to whole satoshis' => ['15000p', 1500, 1];

        yield '21 million bitcoin' => ['21000000', 2_100_000_000_000_000_000, 2_100_000_000_000_000];
    }

    /**
     * @param class-string<PaymentRequestDecodeException> $exception
     */
    #[DataProvider('provideRejectsInvalidHumanReadablePartsCases')]
    public function testRejectsInvalidHumanReadableParts(string $humanReadablePart, string $exception): void
    {
        $this->expectException($exception);

        (new PaymentRequestDecoder(lenient: true))->decode(InvoiceBuilder::valid($humanReadablePart)->build());
    }

    /**
     * @return iterable<string, array{string, class-string<PaymentRequestDecodeException>}>
     */
    public static function provideRejectsInvalidHumanReadablePartsCases(): iterable
    {
        yield 'zero' => ['lnbc0', InvalidAmountException::class];

        yield 'leading zeros' => ['lnbc00', InvalidAmountException::class];

        yield 'leading zero before a multiplier' => ['lnbc01m', InvalidAmountException::class];

        yield 'sub-millisatoshi' => ['lnbc1p', InvalidAmountException::class];

        yield 'invalid multiplier' => ['lnbc2500x', InvalidAmountException::class];

        yield 'two multipliers' => ['lnbc1mu', InvalidAmountException::class];

        yield 'above 21 million bitcoin' => ['lnbc21000001', InvalidAmountException::class];

        yield 'more digits than fit in an int' => ['lnbc99999999999999999999999', InvalidAmountException::class];

        yield 'unknown currency' => ['lnxx', UnknownNetworkVersionException::class];

        yield 'multiplier without amount is read as currency' => ['lnbcm', UnknownNetworkVersionException::class];

        yield 'no currency' => ['ln', UnknownNetworkVersionException::class];

        yield 'not ln' => ['bc', InvalidPaymentRequestException::class];
    }

    /**
     * Rules strict mode enforces. Lenient mode accepts each of these invoices.
     *
     * @param class-string<PaymentRequestDecodeException> $exception
     */
    #[DataProvider('provideStrictRulesCases')]
    public function testStrictRules(InvoiceBuilder $builder, string $exception, string $message): void
    {
        $invoice = $builder->build();

        (new PaymentRequestDecoder(lenient: true))->decode($invoice);

        $this->expectException($exception);
        $this->expectExceptionMessage($message);
        (new PaymentRequestDecoder())->decode($invoice);
    }

    /**
     * @return iterable<string, array{InvoiceBuilder, class-string<PaymentRequestDecodeException>, string}>
     */
    public static function provideStrictRulesCases(): iterable
    {
        $hash = self::bin(InvoiceBuilder::PAYMENT_HASH);
        $secret = self::bin(InvoiceBuilder::PAYMENT_SECRET);
        $withHashAndSecret = InvoiceBuilder::create()->withBytesField(1, $hash)->withBytesField(16, $secret);
        $invalid = InvalidPaymentRequestException::class;

        yield 'no payment secret' => [InvoiceBuilder::create()->withBytesField(1, $hash)->withBytesField(13, 'x'), $invalid, 'no payment secret (s)'];

        yield 'two payment secrets' => [InvoiceBuilder::valid()->withBytesField(16, str_repeat("\x22", 32)), $invalid, 'more than one payment secret (s)'];

        yield 'two payment hashes' => [InvoiceBuilder::valid()->withBytesField(1, str_repeat("\x22", 32)), $invalid, 'more than one payment hash (p)'];

        yield 'payment hash of 31 bytes next to a valid one' => [InvoiceBuilder::valid()->withBytesField(1, str_repeat("\x22", 31)), $invalid, 'type 1 must be 52 words long, not 50'];

        yield 'payment secret of the wrong length' => [InvoiceBuilder::create()->withBytesField(1, $hash)->withBytesField(16, $secret.'x')->withBytesField(13, 'x'), $invalid, 'type 16 must be 52 words long'];

        yield 'description hash of the wrong length' => [$withHashAndSecret->withBytesField(13, 'x')->withBytesField(23, str_repeat("\x22", 33)), $invalid, 'type 23 must be 52 words long'];

        yield 'payee node key of the wrong length' => [InvoiceBuilder::valid()->withBytesField(19, str_repeat("\x02", 32)), $invalid, 'type 19 must be 53 words long, not 52'];

        yield 'payee node key that is not on the curve' => [InvoiceBuilder::valid()->withBytesField(19, "\x02".str_repeat("\0", 31)."\x05"), $invalid, 'not a valid public key'];

        yield 'neither description nor description hash' => [$withHashAndSecret, $invalid, 'either one description (d) or one description hash (h)'];

        yield 'both description and description hash' => [InvoiceBuilder::valid()->withBytesField(23, $hash), $invalid, 'either one description (d) or one description hash (h)'];

        yield 'two descriptions' => [InvoiceBuilder::valid()->withBytesField(13, 'y'), $invalid, 'either one description (d) or one description hash (h)'];

        yield 'description that is not UTF-8' => [$withHashAndSecret->withBytesField(13, "caf\xe9"), $invalid, 'not valid UTF-8'];

        yield 'description with a control character' => [$withHashAndSecret->withBytesField(13, "bell\x07"), $invalid, 'control characters'];

        yield 'description with a format character (U+200E)' => [$withHashAndSecret->withBytesField(13, "left\u{200E}right"), $invalid, 'control characters'];

        yield 'description with a private-use character' => [$withHashAndSecret->withBytesField(13, "\u{E000}"), $invalid, 'control characters'];

        yield 'description with a line separator' => [$withHashAndSecret->withBytesField(13, "one\u{2028}two"), $invalid, 'control characters'];

        yield 'expiry with a leading zero' => [InvoiceBuilder::valid()->withIntField(6, 7200, 1), $invalid, 'expiry (x) has leading zeros'];

        yield 'min_final_cltv_expiry_delta with a leading zero' => [InvoiceBuilder::valid()->withIntField(24, 40, 2), $invalid, 'min_final_cltv_expiry_delta (c) has leading zeros'];

        yield 'features with a leading zero' => [InvoiceBuilder::valid()->withField(5, [0, 0b10000, 0b01000, 0]), $invalid, 'features (9) have leading zeros'];

        // Bit 100 is the lowest bit of the 21st word from the end.
        yield 'unknown required feature' => [InvoiceBuilder::valid()->withField(5, array_merge([1], array_fill(0, 20, 0))), UnknownRequiredFeatureException::class, 'unknown feature bits: 100'];

        yield 'basic_mpp without payment_secret' => [InvoiceBuilder::valid()->withField(5, [0b00100, 0, 0, 0]), UnknownRequiredFeatureException::class, 'basic_mpp requires feature payment_secret'];

        yield 'high-S signature with a payee node key' => [InvoiceBuilder::valid()->withBytesField(19, self::bin(InvoiceBuilder::PUBLIC_KEY))->withHighS(), SignatureIncorrectOrMissingException::class, 'not in low-S form'];

        yield 'empty fallback address' => [InvoiceBuilder::valid()->withField(9, []), $invalid, 'fallback address (f) field is empty'];

        yield 'P2PKH fallback of 19 bytes' => [InvoiceBuilder::valid()->withField(9, array_merge([17], InvoiceBuilder::bytesToWords(str_repeat("\x01", 19)))), $invalid, 'fallback address (f) field is invalid'];

        yield 'P2WPKH fallback of 21 bytes' => [InvoiceBuilder::valid()->withField(9, array_merge([0], InvoiceBuilder::bytesToWords(str_repeat("\x01", 21)))), $invalid, 'fallback address (f) field is invalid'];

        yield 'witness version 1 fallback of 1 byte' => [InvoiceBuilder::valid()->withField(9, array_merge([1], InvoiceBuilder::bytesToWords("\x01"))), $invalid, 'fallback address (f) field is invalid'];

        yield 'route hint with a partial hop' => [InvoiceBuilder::valid()->withBytesField(3, str_repeat("\x02", 50)), $invalid, 'routing info (r) field has an invalid length'];

        yield 'empty route hint' => [InvoiceBuilder::valid()->withField(3, []), $invalid, 'routing info (r) field has an invalid length'];
    }

    public function testLenientModeSkipsWhatItCannotUse(): void
    {
        $invoice = InvoiceBuilder::create()
            ->withBytesField(1, str_repeat("\x22", 31))
            ->withBytesField(1, self::bin(InvoiceBuilder::PAYMENT_HASH))
            ->withBytesField(19, "\x02".str_repeat("\0", 31)."\x05")
            ->withField(9, [])
            ->withBytesField(3, str_repeat("\x02", 50))
            ->withBytesField(13, "caf\xe9")
            ->withBytesField(13, 'second')
            ->withHighS()
            ->build()
        ;

        $paymentRequest = (new PaymentRequestDecoder(lenient: true))->decode($invoice);

        // The short `p` is skipped, the invalid `n` ignored in favour of
        // recovery, and the first description kept as it is.
        self::assertSame(InvoiceBuilder::PAYMENT_HASH, $paymentRequest->getPaymentHash());
        self::assertSame(InvoiceBuilder::PUBLIC_KEY, $paymentRequest->getPayeeNodeKey());
        self::assertNull($paymentRequest->getPaymentSecret());
        self::assertSame("caf\xe9", $paymentRequest->getDescription());
        self::assertSame([], $paymentRequest->getFallbackAddresses());
        self::assertSame([], $paymentRequest->getRouteHints());
    }

    public function testUnknownRequiredFeatureBitsAreReported(): void
    {
        $invoice = InvoiceBuilder::valid()->withField(5, array_merge([1], array_fill(0, 20, 0)))->build();

        try {
            (new PaymentRequestDecoder())->decode($invoice);
            self::fail('an unknown required feature was accepted');
        } catch (UnknownRequiredFeatureException $exception) {
            self::assertSame([100], $exception->getFeatureBits());
        }

        self::assertSame([100], (new PaymentRequestDecoder(lenient: true))->decode($invoice)->getFeatures()->getBits());
    }

    public function testUnknownOddFeaturesAndUnknownFallbackVersionsAreIgnored(): void
    {
        $invoice = InvoiceBuilder::valid()
            // Bits 14, 15, 17 and 101 (optional and unknown): 21 words, bit 101
            // is bit 1 of the first word.
            ->withField(5, array_merge([2], array_fill(0, 16, 0), [0b00101, 0b10000, 0, 0]))
            ->withField(9, array_merge([19], InvoiceBuilder::bytesToWords(str_repeat("\x01", 20))))
            ->build()
        ;

        $paymentRequest = (new PaymentRequestDecoder())->decode($invoice);

        self::assertSame([14, 15, 17, 101], $paymentRequest->getFeatures()->getBits());
        self::assertSame([], $paymentRequest->getFallbackAddresses());
    }

    public function testTheFirstOfRepeatedFieldsWins(): void
    {
        $invoice = InvoiceBuilder::valid()
            ->withIntField(6, 60)
            ->withIntField(6, 120)
            ->withIntField(24, 9)
            ->withIntField(24, 144)
            ->withBytesField(19, self::bin(InvoiceBuilder::PUBLIC_KEY))
            ->withBytesField(19, self::bin(self::OTHER_PUBLIC_KEY))
            ->withField(9, array_merge([17], InvoiceBuilder::bytesToWords(str_repeat("\x01", 20))))
            ->withField(9, array_merge([18], InvoiceBuilder::bytesToWords(str_repeat("\x01", 20))))
            ->withBytesField(3, self::bin(self::HOP))
            ->withBytesField(3, self::bin(self::HOP.self::HOP))
            ->build()
        ;

        $paymentRequest = (new PaymentRequestDecoder())->decode($invoice);

        self::assertSame(60, $paymentRequest->getExpiry());
        self::assertSame(9, $paymentRequest->getMinFinalCltvExpiryDelta());
        self::assertSame(InvoiceBuilder::PUBLIC_KEY, $paymentRequest->getPayeeNodeKey());

        // Fallbacks and route hints are all kept, most preferred first.
        self::assertSame([17, 18], array_map(static fn (FallbackAddress $address): int => $address->getVersion(), $paymentRequest->getFallbackAddresses()));
        self::assertSame([1, 2], array_map(static fn (RouteHint $hint): int => \count($hint->getHops()), $paymentRequest->getRouteHints()));
    }

    public function testVerifiesAgainstThePayeeNodeKey(): void
    {
        $decoder = new PaymentRequestDecoder();

        self::assertSame(InvoiceBuilder::PUBLIC_KEY, $decoder->decode(InvoiceBuilder::valid()->withBytesField(19, self::bin(InvoiceBuilder::PUBLIC_KEY))->build())->getPayeeNodeKey());

        $this->expectException(SignatureDoesNotMatchPayeePubkeyDecodeException::class);
        $decoder->decode(InvoiceBuilder::valid()->withBytesField(19, self::bin(self::OTHER_PUBLIC_KEY))->build());
    }

    public function testAcceptsHighSSignaturesWithoutPayeeNodeKey(): void
    {
        $paymentRequest = (new PaymentRequestDecoder())->decode(InvoiceBuilder::valid()->withHighS()->build());

        self::assertSame(InvoiceBuilder::PUBLIC_KEY, $paymentRequest->getPayeeNodeKey());
    }

    public function testIntegerFieldWithLeadingZerosInLenientMode(): void
    {
        $paymentRequest = (new PaymentRequestDecoder(lenient: true))->decode(InvoiceBuilder::valid()->withIntField(6, 7200, 11)->build());

        self::assertSame(7200, $paymentRequest->getExpiry());
    }

    /**
     * Never relaxed, not even in lenient mode.
     *
     * @param class-string<PaymentRequestDecodeException> $exception
     */
    #[DataProvider('provideAlwaysRejectedCases')]
    public function testAlwaysRejected(string $invoice, string $exception, string $message): void
    {
        foreach ([new PaymentRequestDecoder(), new PaymentRequestDecoder(lenient: true)] as $decoder) {
            try {
                $decoder->decode($invoice);
                self::fail('an invalid payment request was accepted');
            } catch (PaymentRequestDecodeException $caught) {
                self::assertInstanceOf($exception, $caught);
                self::assertStringContainsString($message, $caught->getMessage());
            }
        }
    }

    /**
     * @return iterable<string, array{string, class-string<PaymentRequestDecodeException>, string}>
     */
    public static function provideAlwaysRejectedCases(): iterable
    {
        $valid = InvoiceBuilder::valid();
        $invalid = InvalidPaymentRequestException::class;
        $signature = self::bin('8d3ce9e28357337f62da0162d9454df827f83cfe499aeb1c1db349d4d81127425e434ca29929406c23bba1ae8ac6ca32880b38d4bf6ff874024cac34ba9625f1');

        yield 'no payment hash' => [InvoiceBuilder::create()->withBytesField(16, self::bin(InvoiceBuilder::PAYMENT_SECRET))->withBytesField(13, 'x')->build(), $invalid, 'no payment hash (p)'];

        yield 'truncated field header' => [$valid->withRawWords([13, 0])->build(), $invalid, 'tagged field is truncated'];

        yield 'field longer than the invoice' => [$valid->withRawWords([13, 1, 0, 0])->build(), $invalid, 'tagged field is longer than the payment request'];

        yield 'expiry above PHP_INT_MAX' => [$valid->withField(6, array_fill(0, 13, 31))->build(), $invalid, 'integer field is too large'];

        yield 'min_final_cltv_expiry_delta above PHP_INT_MAX' => [$valid->withField(24, array_fill(0, 13, 31))->build(), $invalid, 'integer field is too large'];

        // Past 9999-12-31, which no four-digit year can show.
        yield 'expiry after the year 9999' => [$valid->withIntField(6, 253402300800 - InvoiceBuilder::TIMESTAMP)->build(), $invalid, 'expiry time is out of range'];

        yield 'expiry that overflows when added to the timestamp' => [$valid->withIntField(6, PHP_INT_MAX)->build(), $invalid, 'expiry time is out of range'];

        yield 'recovery id above 3' => [$valid->buildWithSignature($signature, 4), SignatureIncorrectOrMissingException::class, 'recovery id must be between 0 and 3'];

        yield 'signature with r = 0' => [$valid->buildWithSignature(str_repeat("\0", 32).substr($signature, 32), 1), UnrecoverableSignatureException::class, 'out of range'];

        yield 'signature by another key than the payee node key' => [$valid->withBytesField(19, self::bin(self::OTHER_PUBLIC_KEY))->build(), SignatureDoesNotMatchPayeePubkeyDecodeException::class, 'does not match'];

        yield 'too short for a signature' => [Bech32::encode('lnbc', [0]), SignatureIncorrectOrMissingException::class, 'too short'];

        yield 'invalid checksum' => [substr($valid->build(), 0, -1).'q', UnableToDecodeBech32Exception::class, 'checksum'];

        yield 'mixed case' => ['L'.substr($valid->build(), 1), UnableToDecodeBech32Exception::class, 'mixed case'];

        yield 'not bech32 at all' => ['hello world', UnableToDecodeBech32Exception::class, 'invalid characters'];

        yield 'empty string' => ['', UnableToDecodeBech32Exception::class, 'invalid characters'];
    }

    /**
     * Mutated invoices with a valid checksum must decode or throw the
     * library's own exception, and never reach the safety net in decode():
     * that would mean an unexpected error inside the decoder.
     */
    public function testMutatedInvoicesOnlyThrowDecodeExceptions(): void
    {
        $invoices = [
            InvoiceBuilder::valid('lnbc2500u')->withIntField(6, 60)->withBytesField(3, self::bin(self::HOP))->build(),
            InvoiceBuilder::valid('lntbs10m')->withField(9, array_merge([0], InvoiceBuilder::bytesToWords(str_repeat("\x01", 32))))->withField(5, [0b10000, 0b01000, 0])->build(),
        ];

        mt_srand(11);
        $decoders = [new PaymentRequestDecoder(), new PaymentRequestDecoder(lenient: true)];
        for ($i = 0; $i < 300; ++$i) {
            [$humanReadablePart, $words] = Bech32::decode($invoices[$i % 2]);
            for ($change = mt_rand(1, 3); $change > 0; --$change) {
                $position = mt_rand(0, \count($words) - 1);
                match (mt_rand(0, 2)) {
                    0 => $words[$position] = mt_rand(0, 31),
                    1 => array_splice($words, $position, 1),
                    2 => array_splice($words, $position, 0, [mt_rand(0, 31)]),
                };
            }

            $mutated = Bech32::encode($humanReadablePart, array_values($words));
            foreach ($decoders as $decoder) {
                try {
                    $decoder->decode($mutated);
                } catch (PaymentRequestDecodeException $exception) {
                    self::assertStringStartsNotWith('unable to decode payment request:', $exception->getMessage(), $mutated);
                }
            }
        }
    }

    private static function bin(string $hex): string
    {
        return (string) hex2bin($hex);
    }
}
