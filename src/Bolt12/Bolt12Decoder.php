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

namespace Jorijn\Bitcoin\Bolt12;

use Jorijn\Bitcoin\Bolt11\Internal\Bech32;
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

/**
 * Decodes BOLT #12 offers, invoice requests and invoices, and verifies the
 * BIP-340 signatures of the last two.
 *
 * It enforces the rules the specification sets for readers that can be
 * checked from the string alone. Rules that need context are left to the
 * caller: whether the offer is expired (Offer::isExpired()), whether the
 * chain is one you support, and whether an invoice answers the request you
 * sent and arrived through the path you expect.
 *
 * Fetching an invoice for an offer is out of scope: that takes onion
 * messages over a Lightning node.
 *
 * @see https://github.com/lightning/bolts/blob/master/12-offer-encoding.md
 */
final class Bolt12Decoder implements Bolt12DecoderInterface
{
    public const PREFIX_OFFER = 'lno';
    public const PREFIX_INVOICE_REQUEST = 'lnr';
    public const PREFIX_INVOICE = 'lni';

    private const OFFER_CHAINS = 2;
    private const OFFER_METADATA = 4;
    private const OFFER_CURRENCY = 6;
    private const OFFER_AMOUNT = 8;
    private const OFFER_DESCRIPTION = 10;
    private const OFFER_FEATURES = 12;
    private const OFFER_ABSOLUTE_EXPIRY = 14;
    private const OFFER_PATHS = 16;
    private const OFFER_ISSUER = 18;
    private const OFFER_QUANTITY_MAX = 20;
    private const OFFER_ISSUER_ID = 22;

    private const INVREQ_METADATA = 0;
    private const INVREQ_CHAIN = 80;
    private const INVREQ_AMOUNT = 82;
    private const INVREQ_FEATURES = 84;
    private const INVREQ_QUANTITY = 86;
    private const INVREQ_PAYER_ID = 88;
    private const INVREQ_PAYER_NOTE = 89;
    private const INVREQ_PATHS = 90;
    private const INVREQ_BIP_353_NAME = 91;

    private const INVOICE_PATHS = 160;
    private const INVOICE_BLINDEDPAY = 162;
    private const INVOICE_CREATED_AT = 164;
    private const INVOICE_RELATIVE_EXPIRY = 166;
    private const INVOICE_PAYMENT_HASH = 168;
    private const INVOICE_AMOUNT = 170;
    private const INVOICE_FALLBACKS = 172;
    private const INVOICE_FEATURES = 174;
    private const INVOICE_NODE_ID = 176;

    private const SIGNATURE = 240;

    private const OFFER_TYPES = [
        self::OFFER_CHAINS, self::OFFER_METADATA, self::OFFER_CURRENCY, self::OFFER_AMOUNT,
        self::OFFER_DESCRIPTION, self::OFFER_FEATURES, self::OFFER_ABSOLUTE_EXPIRY, self::OFFER_PATHS,
        self::OFFER_ISSUER, self::OFFER_QUANTITY_MAX, self::OFFER_ISSUER_ID,
    ];

    private const INVREQ_TYPES = [
        self::INVREQ_METADATA, self::INVREQ_CHAIN, self::INVREQ_AMOUNT, self::INVREQ_FEATURES,
        self::INVREQ_QUANTITY, self::INVREQ_PAYER_ID, self::INVREQ_PAYER_NOTE, self::INVREQ_PATHS,
        self::INVREQ_BIP_353_NAME,
    ];

    private const INVOICE_TYPES = [
        self::INVOICE_PATHS, self::INVOICE_BLINDEDPAY, self::INVOICE_CREATED_AT, self::INVOICE_RELATIVE_EXPIRY,
        self::INVOICE_PAYMENT_HASH, self::INVOICE_AMOUNT, self::INVOICE_FALLBACKS, self::INVOICE_FEATURES,
        self::INVOICE_NODE_ID,
    ];

    /**
     * Each message type owns its own TLV ranges, so the fields of an offer,
     * its invoice request and its invoice can live in one stream without
     * clashing. The second range of each is for experiments.
     */
    private const OFFER_RANGES = [[1, 79], [1_000_000_000, 1_999_999_999]];
    private const INVREQ_RANGES = [[0, 0], [80, 159], [2_000_000_000, 2_999_999_999]];
    private const INVOICE_RANGES = [[160, 239], [3_000_000_000, 3_999_999_999]];
    private const SIGNATURE_RANGES = [[MerkleTree::SIGNATURE_TYPE_MIN, MerkleTree::SIGNATURE_TYPE_MAX]];

    /** Invoice features this library knows: only multi-part payments so far. */
    private const KNOWN_INVOICE_FEATURES = [Features::MPP];

    public function decode(string $string): Invoice|InvoiceRequest|Offer
    {
        return $this->guard(function () use ($string): Invoice|InvoiceRequest|Offer {
            [$prefix, $records] = $this->parseString($string);

            return match ($prefix) {
                self::PREFIX_OFFER => $this->buildOffer($records),
                self::PREFIX_INVOICE_REQUEST => $this->buildInvoiceRequest($records),
                self::PREFIX_INVOICE => $this->buildInvoice($records),
                // A payer proof needs its own checks and model, and adding it
                // to decode()'s return type would break existing callers.
                PayerProofDecoder::PREFIX => throw new InvalidEncodingException('payer proofs ("lnp1...") are decoded by PayerProofDecoder'),
                default => throw new InvalidEncodingException(\sprintf('unknown BOLT #12 prefix "%s"', $prefix)),
            };
        });
    }

    public function decodeOffer(string $offer): Offer
    {
        return $this->guard(fn (): Offer => $this->buildOffer($this->parseString($offer, self::PREFIX_OFFER)[1]));
    }

    public function decodeInvoiceRequest(string $invoiceRequest): InvoiceRequest
    {
        return $this->guard(fn (): InvoiceRequest => $this->buildInvoiceRequest($this->parseString($invoiceRequest, self::PREFIX_INVOICE_REQUEST)[1]));
    }

    public function decodeInvoice(string $invoice): Invoice
    {
        return $this->guard(fn (): Invoice => $this->buildInvoice($this->parseString($invoice, self::PREFIX_INVOICE)[1]));
    }

    /**
     * Safety net, as in the BOLT #11 decoder: the input comes from outside,
     * and callers rely on catching Bolt12DecodeException alone. Every failure
     * we know of throws one already; anything else is wrapped.
     *
     * @template T
     *
     * @param callable(): T $decode
     *
     * @return T
     */
    private function guard(callable $decode): mixed
    {
        try {
            return $decode();
        } catch (Bolt12DecodeException $exception) {
            throw $exception;
        } catch (\Throwable $exception) {
            throw new MalformedTlvException('unable to decode BOLT #12 string: '.$exception->getMessage(), 0, $exception);
        }
    }

    /**
     * @return array{string, list<TlvRecord>}
     */
    private function parseString(string $string, ?string $expectedPrefix = null): array
    {
        try {
            [$prefix, $bytes] = Bolt12String::decode($string);
        } catch (\InvalidArgumentException $exception) {
            throw new InvalidEncodingException($exception->getMessage(), 0, $exception);
        }

        if (null !== $expectedPrefix && $prefix !== $expectedPrefix) {
            throw new InvalidEncodingException(\sprintf('expected prefix "%s", got "%s"', $expectedPrefix, $prefix));
        }

        try {
            $records = TlvRecord::parseStream($bytes);
        } catch (\InvalidArgumentException $exception) {
            throw new MalformedTlvException($exception->getMessage(), 0, $exception);
        }

        if ([] === $records) {
            throw new MalformedTlvException('message is empty');
        }

        return [$prefix, $records];
    }

    /**
     * @param list<TlvRecord> $records
     */
    private function buildOffer(array $records): Offer
    {
        $fields = $this->index($records, [self::OFFER_RANGES], [self::OFFER_TYPES]);
        $offer = $this->parseOffer($fields[0], $fields[1][0]);

        // An offer must say where to send the invoice request.
        if (null === $offer->getIssuerId() && [] === $offer->getPaths()) {
            throw new InvalidFieldException('offer has neither offer_issuer_id nor offer_paths');
        }

        $this->validateOffer($fields[0]);

        return $offer;
    }

    /**
     * @param list<TlvRecord> $records
     */
    private function buildInvoiceRequest(array $records): InvoiceRequest
    {
        [$fields, [$offerUnknown, $requestUnknown, $signatureUnknown]] = $this->index(
            $records,
            [self::OFFER_RANGES, self::INVREQ_RANGES, self::SIGNATURE_RANGES],
            [self::OFFER_TYPES, self::INVREQ_TYPES, [self::SIGNATURE]],
        );

        $request = $this->parseInvoiceRequest($fields, $offerUnknown, [...$requestUnknown, ...$signatureUnknown]);

        $signature = $request->getSignature();
        if (null === $signature) {
            // A request for an offer must be signed, so the issuer knows the
            // payer holds the key. One without an offer is published by its
            // sender (as a QR code, say), and the specification tells that
            // writer not to sign it.
            if ($request->isForOffer()) {
                throw new InvalidSignatureException('invoice request for an offer has no signature');
            }
        } else {
            $this->verifySignature($records, 'invoice_request', $signature, $request->getPayerId());
        }

        return $request;
    }

    /**
     * @param list<TlvRecord> $records
     */
    private function buildInvoice(array $records): Invoice
    {
        [$fields, [$offerUnknown, $requestUnknown, $invoiceUnknown, $signatureUnknown]] = $this->index(
            $records,
            [self::OFFER_RANGES, self::INVREQ_RANGES, self::INVOICE_RANGES, self::SIGNATURE_RANGES],
            [self::OFFER_TYPES, self::INVREQ_TYPES, self::INVOICE_TYPES, [self::SIGNATURE]],
        );

        // The invoice copies the request without its signature: type 240 is
        // the invoice's own signature here, so keep it out of the request.
        $signatureRecord = $fields[self::SIGNATURE] ?? null;
        unset($fields[self::SIGNATURE]);
        $request = $this->parseInvoiceRequest($fields, $offerUnknown, $requestUnknown);

        foreach ([self::INVOICE_AMOUNT, self::INVOICE_CREATED_AT, self::INVOICE_PAYMENT_HASH, self::INVOICE_NODE_ID] as $type) {
            if (!isset($fields[$type])) {
                throw new InvalidFieldException(\sprintf('invoice has no %s', $this->fieldName($type)));
            }
        }

        $amount = $this->truncated($fields[self::INVOICE_AMOUNT], 8);
        if (null !== $request->getAmount() && $amount !== $request->getAmount()) {
            throw new InvalidFieldException('invoice_amount differs from invreq_amount');
        }

        $createdAt = $this->truncated($fields[self::INVOICE_CREATED_AT], 8);
        $relativeExpiry = isset($fields[self::INVOICE_RELATIVE_EXPIRY])
            ? $this->truncated($fields[self::INVOICE_RELATIVE_EXPIRY], 4)
            : Invoice::DEFAULT_RELATIVE_EXPIRY;
        if ($createdAt > FieldReader::MAX_TIMESTAMP - $relativeExpiry) {
            throw new InvalidFieldException('invoice expiry is out of range');
        }

        $nodeId = FieldReader::point($fields[self::INVOICE_NODE_ID], 'invoice_node_id');

        // An invoice for an offer with an issuer id must come from that key;
        // otherwise anyone could answer a request with their own invoice.
        $issuerId = $request->getOffer()->getIssuerId();
        if (null !== $issuerId && $issuerId !== $nodeId) {
            throw new InvalidFieldException('invoice_node_id is not the offer_issuer_id');
        }

        $features = FieldReader::features($fields[self::INVOICE_FEATURES] ?? null, 'invoice_features', self::KNOWN_INVOICE_FEATURES);

        if (null === $signatureRecord) {
            throw new InvalidSignatureException('invoice has no signature');
        }

        $signature = FieldReader::signature($signatureRecord);
        $this->verifySignature($records, 'invoice', $signature, $nodeId);

        return new Invoice(
            $request,
            $this->paymentPaths($fields[self::INVOICE_PATHS] ?? null, $fields[self::INVOICE_BLINDEDPAY] ?? null),
            $createdAt,
            $relativeExpiry,
            FieldReader::fixed($fields[self::INVOICE_PAYMENT_HASH], 32, 'invoice_payment_hash'),
            $amount,
            $this->fallbackAddresses($fields[self::INVOICE_FALLBACKS] ?? null, $request->getChain()),
            $features,
            $nodeId,
            $signature,
            [...$invoiceUnknown, ...$signatureUnknown],
        );
    }

    /**
     * Sorts the records by type. Every type must fall in one of the ranges
     * the message allows; a known type is kept by number, an unknown odd one
     * goes to the unknown fields of its range group, and an unknown even one
     * is an error (it is OK to be odd, not to be even).
     *
     * @param list<TlvRecord>             $records
     * @param list<list<array{int, int}>> $rangeGroups
     * @param list<list<int>>             $knownTypes  per range group
     *
     * @return array{array<int, TlvRecord>, list<list<UnknownField>>}
     */
    private function index(array $records, array $rangeGroups, array $knownTypes): array
    {
        $fields = [];
        $unknown = array_fill(0, \count($rangeGroups), []);

        foreach ($records as $record) {
            $group = $this->rangeGroup($record->type, $rangeGroups);
            if (null === $group) {
                throw new InvalidFieldException(\sprintf('TLV type %d is outside the ranges this message allows', $record->type));
            }

            if (\in_array($record->type, $knownTypes[$group], true)) {
                $fields[$record->type] = $record;
            } elseif (0 === $record->type % 2) {
                throw new UnknownRequiredFieldException(\sprintf('unknown even TLV type %d', $record->type), $record->type);
            } else {
                $unknown[$group][] = new UnknownField($record->type, bin2hex($record->value));
            }
        }

        return [$fields, $unknown];
    }

    /**
     * @param list<list<array{int, int}>> $rangeGroups
     */
    private function rangeGroup(int $type, array $rangeGroups): ?int
    {
        foreach ($rangeGroups as $group => $ranges) {
            foreach ($ranges as [$min, $max]) {
                if ($type >= $min && $type <= $max) {
                    return $group;
                }
            }
        }

        return null;
    }

    /**
     * Reads the offer fields. Only checks that every field is well-formed;
     * the rules about how they combine are in validateOffer().
     *
     * @param array<int, TlvRecord> $fields
     * @param list<UnknownField>    $unknownFields
     */
    private function parseOffer(array $fields, array $unknownFields): Offer
    {
        $chains = null;
        if (isset($fields[self::OFFER_CHAINS])) {
            $value = $fields[self::OFFER_CHAINS]->value;
            // No chains at all would make every invoice request impossible.
            if ('' === $value || 0 !== \strlen($value) % 32) {
                throw new MalformedTlvException('offer_chains must hold one or more 32-byte chain hashes');
            }

            $chains = array_map(bin2hex(...), str_split($value, 32));
        }

        return new Offer(
            $chains,
            isset($fields[self::OFFER_METADATA]) ? bin2hex($fields[self::OFFER_METADATA]->value) : null,
            FieldReader::text($fields[self::OFFER_CURRENCY] ?? null, 'offer_currency'),
            isset($fields[self::OFFER_AMOUNT]) ? $this->truncated($fields[self::OFFER_AMOUNT], 8) : null,
            FieldReader::text($fields[self::OFFER_DESCRIPTION] ?? null, 'offer_description'),
            FieldReader::features($fields[self::OFFER_FEATURES] ?? null, 'offer_features'),
            isset($fields[self::OFFER_ABSOLUTE_EXPIRY]) ? FieldReader::timestamp($fields[self::OFFER_ABSOLUTE_EXPIRY], 'offer_absolute_expiry') : null,
            $this->blindedPaths($fields[self::OFFER_PATHS] ?? null, 'offer_paths'),
            FieldReader::text($fields[self::OFFER_ISSUER] ?? null, 'offer_issuer'),
            isset($fields[self::OFFER_QUANTITY_MAX]) ? $this->truncated($fields[self::OFFER_QUANTITY_MAX], 8) : null,
            isset($fields[self::OFFER_ISSUER_ID]) ? FieldReader::point($fields[self::OFFER_ISSUER_ID], 'offer_issuer_id') : null,
            $unknownFields,
        );
    }

    /**
     * The reader rules for offers on how fields combine.
     *
     * @param array<int, TlvRecord> $fields
     */
    private function validateOffer(array $fields): void
    {
        if (isset($fields[self::OFFER_AMOUNT])) {
            if (0 === $this->truncated($fields[self::OFFER_AMOUNT], 8)) {
                throw new InvalidFieldException('offer_amount must be greater than zero');
            }

            // A price without saying what it is for: the payer could not tell
            // what it is paying for.
            if (!isset($fields[self::OFFER_DESCRIPTION])) {
                throw new InvalidFieldException('offer has offer_amount but no offer_description');
            }
        } elseif (isset($fields[self::OFFER_CURRENCY])) {
            throw new InvalidFieldException('offer has offer_currency but no offer_amount');
        }
    }

    /**
     * Reads and checks the invoice request fields (and the offer fields in
     * them), without the signature: buildInvoiceRequest() verifies that, and
     * in an invoice the request is not signed on its own.
     *
     * @param array<int, TlvRecord> $fields
     * @param list<UnknownField>    $offerUnknown
     * @param list<UnknownField>    $requestUnknown
     */
    private function parseInvoiceRequest(array $fields, array $offerUnknown, array $requestUnknown): InvoiceRequest
    {
        foreach ([self::INVREQ_METADATA, self::INVREQ_PAYER_ID] as $type) {
            if (!isset($fields[$type])) {
                throw new InvalidFieldException(\sprintf('invoice request has no %s', $this->fieldName($type)));
            }
        }

        $offer = $this->parseOffer($fields, $offerUnknown);
        $isForOffer = null !== $offer->getIssuerId() || [] !== $offer->getPaths();

        $chain = isset($fields[self::INVREQ_CHAIN]) ? FieldReader::fixed($fields[self::INVREQ_CHAIN], 32, 'invreq_chain') : null;
        $amount = isset($fields[self::INVREQ_AMOUNT]) ? $this->truncated($fields[self::INVREQ_AMOUNT], 8) : null;
        $quantity = isset($fields[self::INVREQ_QUANTITY]) ? $this->truncated($fields[self::INVREQ_QUANTITY], 8) : null;

        if ($isForOffer) {
            $this->validateOffer($fields);
            $this->validateAgainstOffer($offer, $chain, $amount, $quantity);
        } else {
            // Without an offer, the sender fills the offer fields itself, and
            // these three only make sense for an offer.
            foreach ([self::OFFER_CHAINS, self::OFFER_FEATURES, self::OFFER_QUANTITY_MAX] as $type) {
                if (isset($fields[$type])) {
                    throw new InvalidFieldException(\sprintf('invoice request without an offer has %s', $this->fieldName($type)));
                }
            }

            if (null === $amount) {
                throw new InvalidFieldException('invoice request without an offer has no invreq_amount');
            }
        }

        return new InvoiceRequest(
            $offer,
            bin2hex($fields[self::INVREQ_METADATA]->value),
            $chain,
            $amount,
            FieldReader::features($fields[self::INVREQ_FEATURES] ?? null, 'invreq_features'),
            $quantity,
            FieldReader::point($fields[self::INVREQ_PAYER_ID], 'invreq_payer_id'),
            FieldReader::text($fields[self::INVREQ_PAYER_NOTE] ?? null, 'invreq_payer_note'),
            $this->blindedPaths($fields[self::INVREQ_PATHS] ?? null, 'invreq_paths'),
            isset($fields[self::INVREQ_BIP_353_NAME]) ? $this->bip353Name($fields[self::INVREQ_BIP_353_NAME]) : null,
            isset($fields[self::SIGNATURE]) ? FieldReader::signature($fields[self::SIGNATURE]) : null,
            $requestUnknown,
        );
    }

    /**
     * The reader rules for a request that answers an offer, as far as they
     * can be checked without knowing the offer's issuer: the chain, the
     * quantity and the amount must fit the offer.
     */
    private function validateAgainstOffer(Offer $offer, ?string $chain, ?int $amount, ?int $quantity): void
    {
        if (!$offer->isForChain($chain ?? Chain::BITCOIN)) {
            throw new InvalidFieldException('invoice request is for a chain the offer is not for');
        }

        $quantityMax = $offer->getQuantityMax();
        if (null === $quantityMax) {
            if (null !== $quantity) {
                throw new InvalidFieldException('invoice request has invreq_quantity but the offer has no offer_quantity_max');
            }
        } elseif (null === $quantity || 0 === $quantity || (0 !== $quantityMax && $quantity > $quantityMax)) {
            throw new InvalidFieldException('invreq_quantity is missing, zero or above offer_quantity_max');
        }

        $offerAmount = $offer->getAmount();
        if (null === $offerAmount) {
            // A donation-style offer: the payer has to name the amount.
            if (null === $amount) {
                throw new InvalidFieldException('invoice request has no invreq_amount for an offer without offer_amount');
            }

            return;
        }

        // Only an amount in millisatoshis can be compared; converting a price
        // in another currency takes an exchange rate, which is the issuer's call.
        $offerMilliSatoshis = $offer->getMilliSatoshis();
        if (null !== $amount && null !== $offerMilliSatoshis) {
            $items = $quantity ?? 1;
            if ($offerMilliSatoshis > intdiv(PHP_INT_MAX, $items) || $amount < $offerMilliSatoshis * $items) {
                throw new InvalidFieldException('invreq_amount is less than the offer asks');
            }
        }
    }

    /**
     * @param list<TlvRecord> $records the whole message, signature included
     */
    private function verifySignature(array $records, string $messageName, string $signature, string $publicKey): void
    {
        $hash = MerkleTree::signatureHash($messageName, 'signature', MerkleTree::root($records));

        if (!Secp256k1::verifySchnorr($hash, (string) hex2bin($signature), (string) hex2bin($publicKey))) {
            throw new InvalidSignatureException(\sprintf('%s signature is not valid', $messageName));
        }
    }

    /**
     * @return list<BlindedPath>
     */
    private function blindedPaths(?TlvRecord $record, string $name): array
    {
        if (null === $record) {
            return [];
        }

        $reader = new ByteReader($record->value);
        $paths = [];

        try {
            do {
                // first_node_id: a first byte of 0 or 1 starts a 9-byte
                // channel reference, 2 or 3 a 33-byte public key.
                $first = $reader->read(1);
                $introductionNode = $first.$reader->read(\in_array(\ord($first), [0, 1], true) ? 8 : 32);
                if (33 === \strlen($introductionNode) && !Secp256k1::isValidPublicKey($introductionNode)) {
                    throw new InvalidFieldException(\sprintf('%s has an invalid first_node_id', $name));
                }

                $firstPathKey = $reader->read(33);
                if (!Secp256k1::isValidPublicKey($firstPathKey)) {
                    throw new InvalidFieldException(\sprintf('%s has an invalid first_path_key', $name));
                }

                $paths[] = new BlindedPath(bin2hex($introductionNode), bin2hex($firstPathKey), $this->blindedHops($reader, $name));
            } while (!$reader->isAtEnd());
        } catch (\InvalidArgumentException $exception) {
            throw new MalformedTlvException(\sprintf('%s is malformed: %s', $name, $exception->getMessage()), 0, $exception);
        }

        return $paths;
    }

    /**
     * @return list<BlindedHop>
     */
    private function blindedHops(ByteReader $reader, string $name): array
    {
        $count = $reader->readU8();
        // A path without hops leads nowhere.
        if (0 === $count) {
            throw new InvalidFieldException(\sprintf('%s has a blinded path without hops', $name));
        }

        $hops = [];
        for ($i = 0; $i < $count; ++$i) {
            $blindedNodeId = $reader->read(33);
            if (!Secp256k1::isValidPublicKey($blindedNodeId)) {
                throw new InvalidFieldException(\sprintf('%s has an invalid blinded_node_id', $name));
            }

            $hops[] = new BlindedHop(bin2hex($blindedNodeId), bin2hex($reader->read($reader->readU16())));
        }

        return $hops;
    }

    /**
     * Pairs invoice_paths with invoice_blindedpay, which must have exactly
     * one entry per path.
     *
     * @return list<PaymentPath>
     */
    private function paymentPaths(?TlvRecord $pathsRecord, ?TlvRecord $payInfoRecord): array
    {
        $paths = $this->blindedPaths($pathsRecord, 'invoice_paths');
        if ([] === $paths) {
            throw new InvalidFieldException('invoice has no invoice_paths');
        }

        if (null === $payInfoRecord) {
            throw new InvalidFieldException('invoice has no invoice_blindedpay');
        }

        $reader = new ByteReader($payInfoRecord->value);
        $paymentPaths = [];

        try {
            while (!$reader->isAtEnd()) {
                $path = $paths[\count($paymentPaths)] ?? null;
                if (null === $path) {
                    throw new InvalidFieldException('invoice_blindedpay has more entries than invoice_paths');
                }

                $feeBase = $reader->readU32();
                $feeProportional = $reader->readU32();
                $cltvExpiryDelta = $reader->readU16();
                $htlcMinimum = $reader->readU64();
                // A maximum beyond PHP_INT_MAX is more than all bitcoin there
                // will ever be, so in practice "no maximum": cap it.
                $htlcMaximumBytes = $reader->read(8);
                $htlcMaximum = \ord($htlcMaximumBytes[0]) >= 0x80 ? PHP_INT_MAX : (new ByteReader($htlcMaximumBytes))->readU64();
                // Unknown required features make this one path unusable, not
                // the invoice invalid: see the check after the loop.
                $features = Features::fromBytes($reader->read($reader->readU16()));

                $paymentPaths[] = new PaymentPath($path, $feeBase, $feeProportional, $cltvExpiryDelta, $htlcMinimum, $htlcMaximum, $features);
            }
        } catch (\InvalidArgumentException $exception) {
            throw new MalformedTlvException('invoice_blindedpay is malformed: '.$exception->getMessage(), 0, $exception);
        }

        if (\count($paymentPaths) !== \count($paths)) {
            throw new InvalidFieldException('invoice_blindedpay does not have one entry per invoice_paths entry');
        }

        // A path that requires a feature we do not know cannot be used; with
        // no usable path left, the invoice cannot be paid at all.
        if ([] === array_filter($paymentPaths, static fn (PaymentPath $path): bool => $path->isUsable())) {
            throw new InvalidFieldException('invoice has no blinded path without unknown required features');
        }

        return $paymentPaths;
    }

    /**
     * @return list<FallbackAddress>
     */
    private function fallbackAddresses(?TlvRecord $record, string $chain): array
    {
        if (null === $record) {
            return [];
        }

        $network = Chain::toNetwork($chain);
        $reader = new ByteReader($record->value);
        $addresses = [];

        try {
            while (!$reader->isAtEnd()) {
                $version = $reader->readU8();
                $program = $reader->read($reader->readU16());

                // The reader must ignore, not reject, entries it cannot use:
                // versions above 16 and programs that are not 2 to 40 bytes,
                // or not 20 or 32 for version 0 (BIP 141).
                $length = \strlen($program);
                if ($version > 16 || $length < 2 || $length > 40 || (0 === $version && 20 !== $length && 32 !== $length)) {
                    continue;
                }

                $addresses[] = new FallbackAddress(
                    $version,
                    bin2hex($program),
                    null === $network ? null : Bech32::encodeSegwitAddress($network->segwitPrefix(), $version, $program),
                );
            }
        } catch (\InvalidArgumentException $exception) {
            throw new MalformedTlvException('invoice_fallbacks is malformed: '.$exception->getMessage(), 0, $exception);
        }

        return $addresses;
    }

    /**
     * BIP 353 names may only use letters, digits, "-", "_" and ".".
     */
    private function bip353Name(TlvRecord $record): string
    {
        $reader = new ByteReader($record->value);

        try {
            $name = $reader->read($reader->readU8());
            $domain = $reader->read($reader->readU8());
        } catch (\InvalidArgumentException $exception) {
            throw new MalformedTlvException('invreq_bip_353_name is malformed: '.$exception->getMessage(), 0, $exception);
        }

        if (!$reader->isAtEnd()) {
            throw new MalformedTlvException('invreq_bip_353_name has trailing bytes');
        }

        if (1 !== preg_match('/^[0-9a-zA-Z._-]*$/', $name) || 1 !== preg_match('/^[0-9a-zA-Z._-]*$/', $domain)) {
            throw new InvalidFieldException('invreq_bip_353_name contains characters BIP 353 does not allow');
        }

        return $name.'@'.$domain;
    }

    private function truncated(TlvRecord $record, int $maxBytes): int
    {
        return FieldReader::truncated($record, $maxBytes, $this->fieldName($record->type));
    }

    private function fieldName(int $type): string
    {
        return match ($type) {
            self::OFFER_CHAINS => 'offer_chains',
            self::OFFER_AMOUNT => 'offer_amount',
            self::OFFER_FEATURES => 'offer_features',
            self::OFFER_ABSOLUTE_EXPIRY => 'offer_absolute_expiry',
            self::OFFER_QUANTITY_MAX => 'offer_quantity_max',
            self::INVREQ_METADATA => 'invreq_metadata',
            self::INVREQ_AMOUNT => 'invreq_amount',
            self::INVREQ_QUANTITY => 'invreq_quantity',
            self::INVREQ_PAYER_ID => 'invreq_payer_id',
            self::INVOICE_CREATED_AT => 'invoice_created_at',
            self::INVOICE_RELATIVE_EXPIRY => 'invoice_relative_expiry',
            self::INVOICE_PAYMENT_HASH => 'invoice_payment_hash',
            self::INVOICE_AMOUNT => 'invoice_amount',
            self::INVOICE_NODE_ID => 'invoice_node_id',
            default => 'type '.$type,
        };
    }
}
