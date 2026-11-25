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

use Jorijn\Bitcoin\Bolt11\Internal\Secp256k1;
use Jorijn\Bitcoin\Bolt12\Exception\Bolt12DecodeException;
use Jorijn\Bitcoin\Bolt12\Exception\InvalidFieldException;
use Jorijn\Bitcoin\Bolt12\Exception\InvalidSignatureException;
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
use Tests\Jorijn\Bitcoin\Bolt12\Support\PayerProofBuilder;

/**
 * Runs the official BOLT #12 payer proof vectors (see tests/Fixtures/README.md).
 *
 * Every invalid vector must fail with the exception its reason implies, not
 * just any exception: the reason names one broken rule, and a proof that
 * fails on another rule would leave that one untested.
 *
 * @phpstan-type Field array{type: int, len: int, hex: string, included?: bool}
 * @phpstan-type Vector array{name: string, input: array{invoice: string, invoice_hex: string, preimage: string, note?: string, invoice_fields: list<Field>}, working: array{invoice_merkle_root: string, invoice_signature: string, proof_merkle_root: string, proof_leaf_hashes: list<string>, proof_omitted_tlvs: list<int>, proof_missing_hashes: list<string>}, result: array{payer_sig: string, bech32: string, proof_fields: list<Field>}}
 * @phpstan-type Keys array<string, array{secret: string, pubkey: string}>
 *
 * @internal
 */
#[CoversClass(PayerProofDecoder::class)]
#[CoversClass(PayerProof::class)]
#[CoversClass(MerkleTree::class)]
#[UsesClass(Bolt12String::class)]
#[UsesClass(ByteReader::class)]
#[UsesClass(TlvRecord::class)]
#[UsesClass(FieldReader::class)]
#[UsesClass(Features::class)]
#[UsesClass(UnknownField::class)]
#[UsesClass(Secp256k1::class)]
final class PayerProofTestVectorsTest extends TestCase
{
    private const FIXTURE = __DIR__.'/../../Fixtures/bolt12-payer-proof-test.json';

    /**
     * @param Vector $vector
     * @param Keys   $keys
     */
    #[DataProvider('provideValidVectorsCases')]
    public function testValidVectors(array $vector, array $keys): void
    {
        $proof = (new PayerProofDecoder())->decode($vector['result']['bech32']);

        self::assertSame($keys['invreq_payer_id']['pubkey'], $proof->getPayerId());
        self::assertSame($keys['invoice_node_id']['pubkey'], $proof->getNodeId());
        self::assertSame($vector['input']['preimage'], $proof->getPreimage());
        self::assertSame($vector['working']['invoice_signature'], $proof->getInvoiceSignature());
        self::assertSame($vector['result']['payer_sig'], $proof->getProofSignature());
        self::assertSame($vector['input']['note'] ?? null, $proof->getNote());
        self::assertSame($this->invoiceField($vector, 168), $proof->getPaymentHash());

        // Every invoice field the vector shows, and nothing more, by type.
        $shown = [];
        $omitted = 0;
        foreach ($vector['input']['invoice_fields'] as $field) {
            if (MerkleTree::isSignatureType($field['type'])) {
                continue;
            }

            if ($field['included'] ?? false) {
                $shown[$field['type']] = $field['hex'];
            } else {
                ++$omitted;
            }
        }

        self::assertSame($shown, $proof->getDisclosedFields());
        self::assertSame($omitted, $proof->getOmittedFieldCount());

        // The typed getters agree with the raw fields they read.
        self::assertSame(isset($shown[170]) ? (int) hexdec($shown[170]) : null, $proof->getAmount());
        self::assertSame(isset($shown[164]) ? (int) hexdec($shown[164]) : null, $proof->getCreatedAt()?->getTimestamp());
        self::assertSame(isset($shown[22]) ? $keys['offer_issuer_id']['pubkey'] : null, $proof->getIssuerId());
    }

    /**
     * @return iterable<string, array{Vector, Keys}>
     */
    public static function provideValidVectorsCases(): iterable
    {
        /** @var array{keys: Keys, valid_vectors: list<Vector>} $fixture */
        $fixture = json_decode((string) file_get_contents(self::FIXTURE), true, 512, JSON_THROW_ON_ERROR);
        foreach ($fixture['valid_vectors'] as $vector) {
            yield $vector['name'] => [$vector, $fixture['keys']];
        }
    }

    /**
     * The test writer reproduces each vector byte for byte, signature
     * included: the rule tests in PayerProofDecoderTest build their proofs
     * with it, so it has to write what the specification says.
     *
     * @param Vector $vector
     */
    #[DataProvider('provideVectorsCases')]
    public function testBuilderWritesTheVectors(array $vector): void
    {
        $included = [];
        foreach ($vector['input']['invoice_fields'] as $field) {
            if ($field['included'] ?? false) {
                $included[] = $field['type'];
            }
        }

        $builder = PayerProofBuilder::forInvoiceBytes((string) hex2bin($vector['input']['invoice_hex']), $vector['input']['preimage'])->including(...$included);
        if (isset($vector['input']['note'])) {
            $builder = $builder->withNote($vector['input']['note']);
        }

        // One vector writes an empty proof_omitted_tlvs, which a writer may leave out.
        if ([] === $vector['working']['proof_omitted_tlvs'] && str_contains($vector['name'], 'explicit')) {
            $builder = $builder->withExplicitEmptyMarkers();
        }

        $records = $builder->proofRecords();
        self::assertSame(implode('', $vector['working']['proof_leaf_hashes']), bin2hex($records[1004]));
        self::assertSame(implode('', $vector['working']['proof_missing_hashes']), bin2hex($records[1003]));
        self::assertSame($vector['result']['bech32'], $builder->encode());
    }

    /**
     * The merkle roots of the vectors' working, computed as the reader does.
     *
     * @param Vector $vector
     */
    #[DataProvider('provideVectorsCases')]
    public function testMerkleRoots(array $vector): void
    {
        $records = TlvRecord::parseStream(Bolt12String::decode($vector['result']['bech32'])[1]);
        self::assertSame($vector['working']['proof_merkle_root'], bin2hex(MerkleTree::root($records)));

        // Rebuild the invoice root from the shown leaves and missing hashes.
        $fields = [];
        foreach ($records as $record) {
            $fields[$record->type] = $record;
        }

        $nonces = str_split($fields[1004]->value, 32);
        $leaves = [0 => null];
        foreach ($vector['working']['proof_omitted_tlvs'] as $marker) {
            $leaves[$marker] = null;
        }

        $i = 0;
        foreach ($records as $record) {
            if (($record->type >= 1 && $record->type <= 239) || ($record->type >= 1_000_000_000 && $record->type <= 3_999_999_999)) {
                $leaves[$record->type] = MerkleTree::leaf($record->raw, $nonces[$i++]);
            }
        }

        ksort($leaves);
        $missing = array_map(static fn (string $hash): string => (string) hex2bin($hash), $vector['working']['proof_missing_hashes']);

        self::assertSame($vector['working']['invoice_merkle_root'], bin2hex(MerkleTree::reconstructRoot(array_values($leaves), $missing)));
    }

    /**
     * @return iterable<string, array{Vector}>
     */
    public static function provideVectorsCases(): iterable
    {
        foreach (self::provideValidVectorsCases() as $name => [$vector]) {
            yield $name => [$vector];
        }
    }

    /**
     * @param class-string<Bolt12DecodeException> $exception
     */
    #[DataProvider('provideInvalidVectorsCases')]
    public function testInvalidVectors(string $bech32, string $exception, string $message): void
    {
        $this->expectException($exception);
        $this->expectExceptionMessageMatches($message);

        (new PayerProofDecoder())->decode($bech32);
    }

    /**
     * @return iterable<string, array{string, class-string<Bolt12DecodeException>, string}>
     */
    public static function provideInvalidVectorsCases(): iterable
    {
        /** @var array{invalid_vectors: list<array{reason: string, bech32: string}>} $fixture */
        $fixture = json_decode((string) file_get_contents(self::FIXTURE), true, 512, JSON_THROW_ON_ERROR);

        // What each reason must fail with: the exception and its message.
        /** @var array<string, array{class-string<Bolt12DecodeException>, string}> $expected */
        $expected = [
            'missing_invreq_payer_id' => [InvalidFieldException::class, '/no invreq_payer_id/'],
            'missing_invoice_payment_hash' => [InvalidFieldException::class, '/no invoice_payment_hash/'],
            'missing_invoice_node_id' => [InvalidFieldException::class, '/no invoice_node_id/'],
            'missing_signature' => [InvalidFieldException::class, '/no signature/'],
            'missing_proof_preimage' => [InvalidFieldException::class, '/no proof_preimage/'],
            'missing_proof_missing_hashes' => [InvalidFieldException::class, '/no proof_missing_hashes/'],
            'missing_proof_leaf_hashes' => [InvalidFieldException::class, '/no proof_leaf_hashes/'],
            'missing_proof_signature' => [InvalidFieldException::class, '/no proof_signature/'],
            'wrong_proof_preimage' => [InvalidFieldException::class, '/proof_preimage does not hash/'],
            'proof_omitted_tlvs_not_ascending' => [InvalidFieldException::class, '/ascending/'],
            'proof_omitted_tlvs_contains_zero' => [InvalidFieldException::class, '/contains 0/'],
            'proof_omitted_tlvs_contains_signature_field' => [InvalidFieldException::class, '/outside the invoice ranges/'],
            'proof_omitted_tlvs_contains_proof_field' => [InvalidFieldException::class, '/outside the invoice ranges/'],
            'proof_omitted_tlvs_contains_high_field' => [InvalidFieldException::class, '/outside the invoice ranges/'],
            'proof_omitted_tlvs_contains_included_tlv_field' => [InvalidFieldException::class, '/type of a shown field/'],
            'proof_omitted_tlvs_not_sequential' => [InvalidFieldException::class, '/was due/'],
            'proof_leaf_hashes_too_few' => [InvalidFieldException::class, '/proof_leaf_hashes has \d+ hashes/'],
            'proof_leaf_hashes_too_many' => [InvalidFieldException::class, '/proof_leaf_hashes has \d+ hashes/'],
            'proof_missing_hashes_too_few' => [InvalidFieldException::class, '/too few missing hashes/'],
            'proof_missing_hashes_too_many' => [InvalidFieldException::class, '/missing hashes given/'],
            'wrong_invoice_signature' => [InvalidSignatureException::class, '/invoice signature is not valid/'],
            'wrong_proof_signature' => [InvalidSignatureException::class, '/proof_signature is not valid/'],
            'contains_invreq_metadata' => [InvalidFieldException::class, '/must not include invreq_metadata/'],
        ];

        foreach ($fixture['invalid_vectors'] as $vector) {
            if (!isset($expected[$vector['reason']])) {
                self::fail('no expectation for invalid vector '.$vector['reason']);
            }

            [$exception, $message] = $expected[$vector['reason']];

            yield $vector['reason'] => [$vector['bech32'], $exception, $message];
        }
    }

    /**
     * @param Vector $vector
     */
    private function invoiceField(array $vector, int $type): string
    {
        foreach ($vector['input']['invoice_fields'] as $field) {
            if ($field['type'] === $type) {
                return $field['hex'];
            }
        }

        self::fail('vector has no field '.$type);
    }
}
