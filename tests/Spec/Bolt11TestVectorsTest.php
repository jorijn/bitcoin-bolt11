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

use Jorijn\Bitcoin\Bolt11\Exception\PaymentRequestDecodeException;
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

/**
 * Runs the official BOLT #11 test vectors (see tests/Fixtures/README.md).
 *
 * All 31 are gated: strict mode must accept every valid vector and reject
 * every invalid one. Lenient mode must still reject the ones that break a
 * rule it never relaxes.
 *
 * @internal
 */
#[CoversClass(PaymentRequestDecoder::class)]
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
final class Bolt11TestVectorsTest extends TestCase
{
    private const FIXTURE = __DIR__.'/../Fixtures/bolt11-invoice-test.json';

    /** The key every example is signed with (vector 15 and the invalid ones aside). */
    private const PAYEE = '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad';

    private const PAYMENT_HASH = '0001020304050607080900010203040506070809000102030405060708090102';
    private const PAYMENT_SECRET = '1111111111111111111111111111111111111111111111111111111111111111';
    private const DESCRIPTION_HASH = '3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1';

    /**
     * Invalid vectors that only break a rule lenient mode relaxes, so lenient
     * mode accepts them. Every other invalid vector stays invalid.
     */
    private const VALID_WHEN_LENIENT = [
        16 => 'unknown even feature bit',
        17 => '`n` field of the wrong length (skipped)',
        19 => 'two distinct `p` fields (the first wins)',
        20 => 'the same `p` field twice',
        21 => 'two distinct `s` fields (the first wins)',
        29 => 'no `s` field',
        30 => 'high-S signature with an `n` field (and two `s` fields)',
    ];

    #[DataProvider('provideVectorCases')]
    public function testStrictModeFollowsTheSpecification(string $invoice, bool $valid, string $description, int $index): void
    {
        self::assertSame($valid, self::accepts(new PaymentRequestDecoder(), $invoice), \sprintf('vector %d: %s', $index, $description));
    }

    #[DataProvider('provideVectorCases')]
    public function testLenientModeOnlyRelaxesTheDocumentedRules(string $invoice, bool $valid, string $description, int $index): void
    {
        $expected = $valid || \array_key_exists($index, self::VALID_WHEN_LENIENT);

        self::assertSame($expected, self::accepts(new PaymentRequestDecoder(lenient: true), $invoice), \sprintf('vector %d: %s', $index, $description));
    }

    /**
     * @return iterable<string, array{string, bool, string, int}>
     */
    public static function provideVectorCases(): iterable
    {
        foreach (self::loadVectors() as $index => $vector) {
            // Descriptions are long and not unique, so prefix the fixture index.
            // The first 80 characters, not bytes: a cut in a multi-byte character is invalid UTF-8.
            $label = \sprintf('#%02d %s: %s', $index, $vector['valid'] ? 'valid' : 'invalid', preg_replace('/^(.{80}).+$/us', '$1...', $vector['description']));

            yield $label => [$vector['invoice'], $vector['valid'], $vector['description'], $index];
        }
    }

    /**
     * The values each valid vector describes, checked field by field.
     *
     * @param array<string, mixed> $expected a subset of PaymentRequest::toArray()
     */
    #[DataProvider('provideDecodedValuesCases')]
    public function testDecodedValues(int $index, array $expected): void
    {
        $actual = (new PaymentRequestDecoder())->decode(self::loadVectors()[$index]['invoice'])->toArray();

        foreach ($expected as $key => $value) {
            self::assertSame($value, $actual[$key], \sprintf('vector %d: %s', $index, $key));
        }
    }

    /**
     * @return iterable<string, array{int, array<string, mixed>}>
     */
    public static function provideDecodedValuesCases(): iterable
    {
        $common = [
            'network' => 'bc',
            'timestamp' => 1496314658,
            'payee_node_key' => self::PAYEE,
            'payment_hash' => self::PAYMENT_HASH,
            'payment_secret' => self::PAYMENT_SECRET,
            'features' => [8, 14],
            'expiry' => 3600,
            'min_final_cltv_expiry_delta' => 18,
        ];

        yield 'donation without an amount' => [0, $common + [
            'prefix' => 'lnbc',
            'milli_satoshis' => null,
            'satoshis' => null,
            'description' => 'Please consider supporting this project',
            'description_hash' => null,
            'signature' => '8d3ce9e28357337f62da0162d9454df827f83cfe499aeb1c1db349d4d81127425e434ca29929406c23bba1ae8ac6ca32880b38d4bf6ff874024cac34ba9625f1',
            'recovery_flag' => 1,
        ]];

        yield '$3 coffee, one minute' => [1, ['milli_satoshis' => 250_000_000, 'satoshis' => 250_000, 'description' => '1 cup coffee', 'expiry' => 60, 'expiry_timestamp' => 1496314718] + $common];

        yield 'UTF-8 description' => [2, ['description' => 'ナンセンス 1杯', 'expiry' => 60] + $common];

        yield 'description hash' => [3, ['milli_satoshis' => 2_000_000_000, 'description' => null, 'description_hash' => self::DESCRIPTION_HASH] + $common];

        yield 'testnet with a P2PKH fallback' => [4, [
            'network' => 'tb',
            'prefix' => 'lntb20m',
            'fallback_addresses' => [['version' => 17, 'program' => '3172b5654f6683c8fb146959d347ce303cae4ca7', 'address' => 'mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP']],
        ] + $common];

        yield 'mainnet P2PKH fallback and a two-hop route hint' => [5, [
            'fallback_addresses' => [['version' => 17, 'program' => '04b61f7dc1ea0dc99424464cc4064dc564d91e89', 'address' => '1RustyRX2oai4EYYDpQGWvEL62BBGqN9T']],
            'route_hints' => [[
                ['public_key' => '029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255', 'short_channel_id' => '0102030405060708', 'fee_base_msat' => 1, 'fee_proportional_millionths' => 20, 'cltv_expiry_delta' => 3],
                ['public_key' => '039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255', 'short_channel_id' => '030405060708090a', 'fee_base_msat' => 2, 'fee_proportional_millionths' => 30, 'cltv_expiry_delta' => 4],
            ]],
        ] + $common];

        yield 'P2SH fallback' => [6, ['fallback_addresses' => [['version' => 18, 'program' => '8f55563b9a19f321c211e9b9f38cdf686ea07845', 'address' => '3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX']]] + $common];

        yield 'P2WPKH fallback' => [7, ['fallback_addresses' => [['version' => 0, 'program' => '751e76e8199196d454941c45d1b3a323f1433bd6', 'address' => 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4']]] + $common];

        yield 'P2WSH fallback' => [8, ['fallback_addresses' => [['version' => 0, 'program' => '1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262', 'address' => 'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3']]] + $common];

        yield 'P2TR fallback (bech32m)' => [9, ['fallback_addresses' => [['version' => 1, 'program' => '0adac43daa9c8a5a68e09ea10692b82226ee190e572db9b90e17a410484ab405', 'address' => 'bc1pptdvg0d2nj99568qn6ssdy4cygnwuxgw2ukmnwgwz7jpqjz2kszse2s3lm']]] + $common];

        yield 'pico-bitcoin amount, expiry of a week' => [10, [
            'prefix' => 'lnbc9678785340p',
            'milli_satoshis' => 967_878_534,
            'satoshis' => 967_878,
            'timestamp' => 1572468703,
            'expiry' => 604800,
            'min_final_cltv_expiry_delta' => 10,
            'payment_hash' => '462264ede7e14047e9b249da94fefc47f41f7d02ee9b091815a5506bc8abf75f',
            'description' => 'Blockstream Store: 88.85 USD for Blockstream Ledger Nano S x 1, "Back In My Day" Sticker x 2, "I Got Lightning Working" Sticker x 2 and 1 more items',
            'route_hints' => [[['public_key' => '03d06758583bb5154774a6eb221b1276c9e82d65bbaceca806d90e20c108f4b1c7', 'short_channel_id' => '08fe4e000cf00001', 'fee_base_msat' => 1000, 'fee_proportional_millionths' => 2500, 'cltv_expiry_delta' => 40]]],
        ]];

        $coffeeBeans = ['milli_satoshis' => 2_500_000_000, 'description' => 'coffee beans', 'features' => [8, 14, 99]] + $common;

        yield 'unknown odd feature 99 is ignored' => [11, $coffeeBeans];

        yield 'upper case' => [12, $coffeeBeans + ['prefix' => 'lnbc25m']];

        yield 'unknown field and a fallback of unknown version are skipped' => [13, $coffeeBeans + [
            'fallback_addresses' => [],
            'unknown_fields' => [['type' => 10, 'words' => [0, 0, 0]]],
        ]];

        yield 'payment metadata' => [14, ['metadata' => '01fafaf0', 'features' => [8, 14, 48], 'description' => 'payment metadata inside'] + $common];

        // The high-S signature is the low-S one of vector 0 with s negated and
        // the same recovery id, so recovery yields a different key. Accepting it
        // is the point of the vector; libsecp256k1 recovers the same key.
        yield 'high-S signature without `n`: recovery accepts it' => [15, [
            'payee_node_key' => '02d0139ce7427d6dfffd26a326c18be754ef1e64672b42694ba5b23ef6e6e7803d',
            'signature' => '8d3ce9e28357337f62da0162d9454df827f83cfe499aeb1c1db349d4d8112742a1bcb35d66d6bf93dc445e51753935cc32a3a411efd8a7c7bd85b25815a01b50',
        ]];
    }

    private static function accepts(PaymentRequestDecoder $decoder, string $invoice): bool
    {
        try {
            $decoder->decode($invoice);

            return true;
        } catch (PaymentRequestDecodeException) {
            // Any other exception fails the test: every rejection must use the
            // library's own type, so callers need a single catch.
            return false;
        }
    }

    /**
     * @return array<int, array{description: string, valid: bool, invoice: string}>
     */
    private static function loadVectors(): array
    {
        /** @var array<int, array{description: string, valid: bool, invoice: string}> */
        return json_decode((string) file_get_contents(self::FIXTURE), true, 512, JSON_THROW_ON_ERROR);
    }
}
