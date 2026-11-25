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

namespace Tests\Jorijn\Bitcoin\Bolt12\Spec;

use Jorijn\Bitcoin\Bolt11\Internal\Bech32;
use Jorijn\Bitcoin\Bolt11\Internal\Secp256k1;
use Jorijn\Bitcoin\Bolt11\Model\Network;
use Jorijn\Bitcoin\Bolt12\Bolt12Decoder;
use Jorijn\Bitcoin\Bolt12\Exception\Bolt12DecodeException;
use Jorijn\Bitcoin\Bolt12\Internal\Bolt12String;
use Jorijn\Bitcoin\Bolt12\Internal\ByteReader;
use Jorijn\Bitcoin\Bolt12\Internal\FieldReader;
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

/**
 * Runs the official BOLT #12 test vectors (see tests/Fixtures/README.md).
 *
 * Every vector is gated. For valid offers, each field the vector lists is
 * encoded again from the decoded model and compared byte for byte, so a
 * field that decodes to the wrong value fails, not only one that throws.
 *
 * Note: several invalid offer vectors are malformed in more ways than their
 * description says (a wrong length byte, a type written as a two-byte
 * BigSize where it needs four), so they fail on that first. The decoder
 * tests cover those rules with correctly encoded messages.
 *
 * @internal
 */
#[CoversClass(Bolt12Decoder::class)]
#[CoversClass(Bolt12String::class)]
#[CoversClass(TlvRecord::class)]
#[CoversClass(MerkleTree::class)]
#[UsesClass(ByteReader::class)]
#[UsesClass(FieldReader::class)]
#[UsesClass(Bech32::class)]
#[UsesClass(Secp256k1::class)]
#[UsesClass(Offer::class)]
#[UsesClass(InvoiceRequest::class)]
#[UsesClass(Invoice::class)]
#[UsesClass(BlindedPath::class)]
#[UsesClass(BlindedHop::class)]
#[UsesClass(PaymentPath::class)]
#[UsesClass(FallbackAddress::class)]
#[UsesClass(Features::class)]
#[UsesClass(UnknownField::class)]
#[UsesClass(Chain::class)]
#[UsesClass(Network::class)]
final class Bolt12TestVectorsTest extends TestCase
{
    private const FIXTURES = __DIR__.'/../../Fixtures/';

    /**
     * @param array{description: string, valid: bool, bolt12: string, fields?: list<array{type: int, length: int, hex: string}>} $vector
     */
    #[DataProvider('provideOfferVectorsCases')]
    public function testOfferVectors(array $vector): void
    {
        $decoder = new Bolt12Decoder();

        if (!$vector['valid']) {
            $this->expectException(Bolt12DecodeException::class);
            $decoder->decodeOffer($vector['bolt12']);

            return;
        }

        $offer = $decoder->decodeOffer($vector['bolt12']);
        self::assertInstanceOf(Offer::class, $decoder->decode($vector['bolt12']));

        foreach ($vector['fields'] ?? [] as $field) {
            self::assertSame($field['hex'], self::encodeOfferField($offer, $field['type']), \sprintf('type %d', $field['type']));
        }
    }

    /**
     * @return iterable<string, array{array{description: string, valid: bool, bolt12: string, fields?: list<array{type: int, length: int, hex: string}>}}>
     */
    public static function provideOfferVectorsCases(): iterable
    {
        /** @var list<array{description: string, valid: bool, bolt12: string, fields?: list<array{type: int, length: int, hex: string}>}> $vectors */
        $vectors = self::fixture('bolt12-offers-test.json');
        foreach ($vectors as $vector) {
            yield $vector['description'] => [$vector];
        }
    }

    /**
     * @param array{comment: string, valid: bool, string: string} $vector
     */
    #[DataProvider('provideFormatStringVectorsCases')]
    public function testFormatStringVectors(array $vector): void
    {
        if (!$vector['valid']) {
            $this->expectException(Bolt12DecodeException::class);
        }

        // Every valid variant is the same offer, written differently.
        $offer = (new Bolt12Decoder())->decodeOffer($vector['string']);
        self::assertSame('An example description', $offer->getDescription());
    }

    /**
     * @return iterable<string, array{array{comment: string, valid: bool, string: string}}>
     */
    public static function provideFormatStringVectorsCases(): iterable
    {
        /** @var list<array{comment: string, valid: bool, string: string}> $vectors */
        $vectors = self::fixture('bolt12-format-string-test.json');
        foreach ($vectors as $i => $vector) {
            yield $i.': '.$vector['comment'] => [$vector];
        }
    }

    /**
     * @param array{comment: string, merkle: string, bolt12?: string, leaves: list<array<string, string>>, signature?: string} $vector
     */
    #[DataProvider('provideSignatureVectorsCases')]
    public function testSignatureVectors(array $vector): void
    {
        if (isset($vector['bolt12'])) {
            $bytes = Bolt12String::decode($vector['bolt12'])[1];
        } else {
            // The plain merkle examples only list their records, as the
            // argument of each LnLeaf hash.
            $bytes = '';
            foreach ($vector['leaves'] as $leaf) {
                foreach (array_keys($leaf) as $key) {
                    if (1 === preg_match('/LnLeaf`,([0-9a-f]+)\)/', $key, $match)) {
                        $bytes .= (string) hex2bin($match[1]);
                    }
                }
            }
        }

        self::assertSame($vector['merkle'], bin2hex(MerkleTree::root(TlvRecord::parseStream($bytes))));

        if (isset($vector['bolt12'], $vector['signature'])) {
            $request = (new Bolt12Decoder())->decodeInvoiceRequest($vector['bolt12']);
            self::assertSame($vector['signature'], $request->getSignature());
            self::assertSame('A Mathematical Treatise', $request->getOffer()->getDescription());
            self::assertSame('USD', $request->getOffer()->getCurrency());
            self::assertSame(100, $request->getOffer()->getAmount());
            self::assertNull($request->getOffer()->getMilliSatoshis());
            self::assertSame('0000000000000000', $request->getMetadata());
            self::assertTrue($request->isForOffer());
        }
    }

    /**
     * @return iterable<string, array{array{comment: string, merkle: string, bolt12?: string, leaves: list<array<string, string>>, signature?: string}}>
     */
    public static function provideSignatureVectorsCases(): iterable
    {
        /** @var list<array{comment: string, merkle: string, bolt12?: string, leaves: list<array<string, string>>, signature?: string}> $vectors */
        $vectors = self::fixture('bolt12-signature-test.json');
        foreach ($vectors as $i => $vector) {
            yield $i.': '.$vector['comment'] => [$vector];
        }
    }

    /**
     * The payer proof vectors carry signed invoices with a field-by-field
     * breakdown: an independent source of valid invoices.
     *
     * @param array{name: string, input: array{invoice: string, invoice_hex: string, invoice_fields: list<array{type: int, len: int, hex: string}>}, working: array{invoice_merkle_root: string, invoice_signature: string}} $vector
     * @param array<string, array{secret: string, pubkey: string}>                                                                                                                                                           $keys
     */
    #[DataProvider('provideInvoicesFromPayerProofVectorsCases')]
    public function testInvoicesFromPayerProofVectors(array $vector, array $keys): void
    {
        $invoice = (new Bolt12Decoder())->decodeInvoice($vector['input']['invoice']);
        self::assertInstanceOf(Invoice::class, (new Bolt12Decoder())->decode($vector['input']['invoice']));

        self::assertSame($vector['input']['invoice_hex'], bin2hex(Bolt12String::decode($vector['input']['invoice'])[1]));
        self::assertSame($vector['working']['invoice_merkle_root'], bin2hex(MerkleTree::root(TlvRecord::parseStream((string) hex2bin($vector['input']['invoice_hex'])))));
        self::assertSame($vector['working']['invoice_signature'], $invoice->getSignature());
        self::assertSame($keys['invoice_node_id']['pubkey'], $invoice->getNodeId());
        self::assertSame($keys['invreq_payer_id']['pubkey'], $invoice->getInvoiceRequest()->getPayerId());
        self::assertSame($keys['offer_issuer_id']['pubkey'], $invoice->getOffer()->getIssuerId());
        self::assertNull($invoice->getInvoiceRequest()->getSignature());

        $fields = [];
        foreach ($vector['input']['invoice_fields'] as $field) {
            $fields[$field['type']] = $field['hex'];
        }

        self::assertSame($fields[0], $invoice->getInvoiceRequest()->getMetadata());
        self::assertSame($fields[168], $invoice->getPaymentHash());
        self::assertSame((string) hexdec($fields[170]), (string) $invoice->getAmount());
        self::assertSame((int) hexdec($fields[164]), $invoice->getCreatedAt()->getTimestamp());

        $path = $invoice->getPaths()[0]->getPath();
        self::assertSame($keys['first_node_id']['pubkey'], $path->getIntroductionNodeId());
        self::assertSame($keys['first_path_key']['pubkey'], $path->getFirstPathKey());
        self::assertSame($keys['blinded_node_id']['pubkey'], $path->getFinalBlindedNodeId());
        self::assertTrue($invoice->getPaths()[0]->isUsable());
    }

    /**
     * @return iterable<string, array{array{name: string, input: array{invoice: string, invoice_hex: string, invoice_fields: list<array{type: int, len: int, hex: string}>}, working: array{invoice_merkle_root: string, invoice_signature: string}}, array<string, array{secret: string, pubkey: string}>}>
     */
    public static function provideInvoicesFromPayerProofVectorsCases(): iterable
    {
        /** @var array{keys: array<string, array{secret: string, pubkey: string}>, valid_vectors: list<array{name: string, input: array{invoice: string, invoice_hex: string, invoice_fields: list<array{type: int, len: int, hex: string}>}, working: array{invoice_merkle_root: string, invoice_signature: string}}>} $fixture */
        $fixture = self::fixture('bolt12-payer-proof-test.json');
        foreach ($fixture['valid_vectors'] as $vector) {
            yield $vector['name'] => [$vector, $fixture['keys']];
        }
    }

    /**
     * Encodes one offer field again from the decoded model, as hex.
     */
    private static function encodeOfferField(Offer $offer, int $type): string
    {
        $unknown = array_values(array_filter($offer->getUnknownFields(), static fn (UnknownField $field): bool => $field->getType() === $type));
        if ([] !== $unknown) {
            return $unknown[0]->getValue();
        }

        return match ($type) {
            2 => implode('', $offer->getChains()),
            4 => (string) $offer->getMetadata(),
            6 => bin2hex((string) $offer->getCurrency()),
            8 => self::truncated((int) $offer->getAmount()),
            10 => bin2hex((string) $offer->getDescription()),
            12 => self::features($offer->getFeatures()),
            14 => self::truncated((int) $offer->getAbsoluteExpiry()?->getTimestamp()),
            16 => implode('', array_map(self::encodePath(...), $offer->getPaths())),
            18 => bin2hex((string) $offer->getIssuer()),
            20 => self::truncated((int) $offer->getQuantityMax()),
            22 => (string) $offer->getIssuerId(),
            default => self::fail('no encoder for type '.$type),
        };
    }

    private static function encodePath(BlindedPath $path): string
    {
        $hex = $path->getIntroductionNode().$path->getFirstPathKey().\sprintf('%02x', \count($path->getHops()));
        foreach ($path->getHops() as $hop) {
            $hex .= $hop->getBlindedNodeId().\sprintf('%04x', \strlen($hop->getEncryptedRecipientData()) / 2).$hop->getEncryptedRecipientData();
        }

        return $hex;
    }

    private static function truncated(int $value): string
    {
        return bin2hex(ltrim(pack('J', $value), "\0"));
    }

    private static function features(Features $features): string
    {
        $bits = $features->getBits();
        if ([] === $bits) {
            return '';
        }

        $bytes = array_fill(0, intdiv(max($bits), 8) + 1, 0);
        foreach ($bits as $bit) {
            $bytes[\count($bytes) - 1 - intdiv($bit, 8)] |= 1 << ($bit % 8);
        }

        return bin2hex(pack('C*', ...$bytes));
    }

    private static function fixture(string $name): mixed
    {
        return json_decode((string) file_get_contents(self::FIXTURES.$name), true, 512, JSON_THROW_ON_ERROR);
    }
}
