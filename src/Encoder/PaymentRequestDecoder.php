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

namespace Jorijn\Bitcoin\Bolt11\Encoder;

use BitWasp\Bitcoin\Address\PayToPubKeyHashAddress;
use BitWasp\Bitcoin\Address\ScriptHashAddress;
use BitWasp\Bitcoin\Address\SegwitAddress;
use BitWasp\Bitcoin\Bitcoin;
use BitWasp\Bitcoin\Crypto\EcAdapter\Adapter\EcAdapterInterface;
use BitWasp\Bitcoin\Crypto\EcAdapter\Impl\PhpEcc\Serializer\Signature\CompactSignatureSerializer;
use BitWasp\Bitcoin\Crypto\EcAdapter\Key\PublicKeyInterface;
use BitWasp\Bitcoin\Crypto\Hash;
use BitWasp\Bitcoin\Network\NetworkInterface;
use BitWasp\Bitcoin\Network\Networks\Bitcoin as BitcoinMainnet;
use BitWasp\Bitcoin\Network\Networks\BitcoinTestnet;
use BitWasp\Bitcoin\Script\WitnessProgram;
use BitWasp\Buffertools\Buffer;
use BitWasp\Buffertools\BufferInterface;
use BitWasp\Buffertools\Buffertools;
use Jorijn\Bitcoin\Bolt11\Exception\InvalidAmountException;
use Jorijn\Bitcoin\Bolt11\Exception\InvalidPaymentRequestException;
use Jorijn\Bitcoin\Bolt11\Exception\PaymentRequestDecodeException;
use Jorijn\Bitcoin\Bolt11\Exception\SignatureDoesNotMatchPayeePubkeyDecodeException;
use Jorijn\Bitcoin\Bolt11\Exception\SignatureIncorrectOrMissingException;
use Jorijn\Bitcoin\Bolt11\Exception\UnableToDecodeBech32Exception;
use Jorijn\Bitcoin\Bolt11\Exception\UnknownFallbackAddressVersionException;
use Jorijn\Bitcoin\Bolt11\Exception\UnknownNetworkVersionException;
use Jorijn\Bitcoin\Bolt11\Exception\UnrecoverableSignatureException;

use function BitWasp\Bech32\decodeRaw;
use function BitWasp\Bech32\encode;

/**
 * This class decodes BOLT11 payment requests into plain PHP array data.
 *
 * @see https://github.com/lightningnetwork/lnd/blob/master/zpay32/decode.go
 * @see https://github.com/bitcoinjs/bolt11/blob/7251d6d14630f7d8adc3fcc92a3bbfe9000b6e4e/payreq.js
 * @see https://lightningdecoder.com/
 * @see https://github.com/nievk/bolt11/blob/main/bolt11/__init__.py
 *
 * This class is a PHP port from pre-existing BOLT11 libraries.
 */
class PaymentRequestDecoder
{
    public const DIVISORS = [
        'm' => '1000.0000000000',
        'u' => '1000000.0000000000',
        'n' => '1000000000.0000000000',
        'p' => '1000000000000.0000000000',
    ];

    public const MAX_MILLISATS = '2100000000000000000.0000000000';
    public const MILLISATS_PER_BTC = '100000000000.0000000000';
    public const NAME_UNKNOWN_TAG = 'unknownTag';

    public const TAG_CODES = [
        'payment_hash' => 1, // p
        'description' => 13, // d
        'payee_node_key' => 19, // n
        'purpose_commit_hash' => 23,  // h
        'expire_time' => 6, // x
        'min_final_cltv_expiry' => 24, // c
        'fallback_address' => 9, // f
        'routing_info' => 3, // r
        'secret' => 16,
    ];

    /** 9999-12-31T23:59:59+00:00, the last moment \DateTime::ATOM can represent with a four-digit year. */
    private const MAX_EXPIRY_TIMESTAMP = 253402300799;

    /** @var string[] */
    protected $tagNames = [];

    /** @var \Closure[] */
    protected $tagParsers = [];

    /** @var EcAdapterInterface */
    protected $ecAdapter;

    public function __construct(?EcAdapterInterface $ecAdapter = null)
    {
        $this->ecAdapter = $ecAdapter ?? Bitcoin::getEcAdapter();
        $this->tagNames = array_flip(self::TAG_CODES);
        $this->initializeTagParsers();
    }

    /**
     * Decodes a payment request into plain PHP array data.
     *
     * Every invoice that cannot be decoded results in a PaymentRequestDecodeException,
     * so callers can safely decode untrusted input with a single catch block.
     *
     * @return array<string, mixed>
     *
     * @throws PaymentRequestDecodeException
     */
    public function decode(string $paymentRequest): array
    {
        try {
            return $this->decodePaymentRequest($paymentRequest);
        } catch (PaymentRequestDecodeException $exception) {
            throw $exception;
        } catch (\Throwable $exception) {
            // Safety net: the checks in decodePaymentRequest() cover every failure
            // we know of, but the dependencies (bitwasp/*) throw plain \Exception,
            // \RuntimeException or even \ValueError on input they dislike. Malformed
            // invoices come from outside, so none of that may escape the documented
            // exception type. The original stays available as the previous exception.
            throw new InvalidPaymentRequestException('unable to decode payment request: '.$exception->getMessage(), 0, $exception);
        }
    }

    public function convert(array $data, $inBits, $outBits): array
    {
        $value = $bits = 0;
        $maxV = (1 << $outBits) - 1;

        $result = [];
        foreach ($data as $item) {
            $value = ($value << $inBits) | $item;
            $bits += $inBits;

            while ($bits >= $outBits) {
                $bits -= $outBits;
                $result[] = ($value >> $bits) & $maxV;
            }
        }

        if ($bits > 0) {
            $result[] = ($value << ($outBits - $bits)) & $maxV;
        }

        return $result;
    }

    public function hrpToSat(string $hrpString): string
    {
        $milliSatoshis = $this->hrpToMillisat($hrpString);

        // Every bcmath call in this class passes its scale explicitly. Without
        // it, bcmath uses the process-wide bcscale(), which the application (or
        // another library) may have changed; with bcscale(10) this method used to
        // throw for every whole number of satoshis, so `satoshis` went missing.
        //
        // Scale 0 truncates to whole satoshis: what 1.x has always returned under
        // PHP's default scale. A fractional amount is not rejected here (the
        // check that used to sit here could never trigger at scale 0); use the
        // millisatoshi amount when precision matters, see the README.
        return bcdiv($milliSatoshis, self::DIVISORS['m'], 0);
    }

    public function hrpToMillisat(string $hrpString): string
    {
        $divisor = null;
        if (preg_match('/^[munp]$/', substr($hrpString, -1))) {
            $divisor = substr($hrpString, -1);
            $value = substr($hrpString, 0, -1);
        } elseif (preg_match('/^[^munp0-9]$/', substr($hrpString, -1))) {
            throw new InvalidAmountException('not a valid multiplier for the amount');
        } else {
            $value = $hrpString;
        }

        if (!preg_match('/^\d+$/', $value)) {
            throw new InvalidAmountException('not a valid human readable amount');
        }

        // Explicit scales, see hrpToSat(). Under a global bcscale(10), bcmod()
        // below returned "0.0000000000" instead of "0", so every invoice with a
        // `p` amount was rejected. Scale 0 keeps the result identical to what
        // 1.0 returned under PHP's default scale: whole millisatoshis.
        $valueBN = bcmul($value, '1', 10);
        $milliSatoshisBN = $divisor
            ? bcdiv(bcmul($valueBN, self::MILLISATS_PER_BTC, 0), self::DIVISORS[$divisor], 0)
            : bcmul($valueBN, self::MILLISATS_PER_BTC, 0);

        // 1p is a tenth of a millisatoshi, so a `p` amount must be a multiple of 10.
        if (('p' === $divisor && '0' !== bcmod($valueBN, '10', 0))
            || 1 === bccomp($milliSatoshisBN, self::MAX_MILLISATS, 0)) {
            throw new InvalidAmountException('amount is outside valid range');
        }

        return $milliSatoshisBN;
    }

    /**
     * The actual decoding; decode() wraps it so every failure has the library's own exception type.
     *
     * @return array<string, mixed>
     */
    protected function decodePaymentRequest(string $paymentRequest): array
    {
        try {
            [$prefix, $words] = decodeRaw($paymentRequest);
        } catch (\Throwable $exception) {
            throw new UnableToDecodeBech32Exception($exception->getMessage(), $exception->getCode(), $exception);
        }

        if (0 !== strpos($prefix, 'ln')) {
            throw new InvalidPaymentRequestException('data does not appear to be a bolt11 invoice');
        }

        // A signature (104 words) and a timestamp (7 words) are mandatory. Without
        // this check a short invoice reached gmp_init('') in bitwasp/buffertools.
        if (\count($words) < 104 + 7) {
            throw new SignatureIncorrectOrMissingException('signature is missing or incorrect');
        }

        // signature is always 104 words on the end
        // cutting off at the beginning helps since there's no way to tell
        // ahead of time how many tags there are.
        $signatureWords = \array_slice($words, -104);

        // grabbing a copy of the words for later, words will be sliced as we parse.
        $wordsWithoutSignature = \array_slice($words, 0, -104);
        $words = \array_slice($words, 0, -104);
        $signatureBuffer = $this->wordsToBuffer($signatureWords);
        $recoveryID = (int) $signatureBuffer->slice(-1)->getInt();

        // get remaining signature buffer after extracting recovery flag
        $signatureBuffer = $signatureBuffer->slice(0, -1);
        if (!\in_array($recoveryID, [0, 1, 2, 3], true) || 64 !== $signatureBuffer->getSize()) {
            throw new SignatureIncorrectOrMissingException('signature is missing or incorrect');
        }

        // without reverse lookups, can't say that the multiplier at the end must
        // have a number before it, so instead we parse, and if the second group
        // doesn't have anything, there's a good chance the last letter of the
        // coin type got captured by the third group, so just re-regex without
        // the number.
        preg_match('/^ln(\S+?)(\d*)([a-zA-Z]?)$/', $prefix, $prefixMatches);

        if ($prefixMatches && !$prefixMatches[2]) {
            preg_match('/^ln(\S+)$/', $prefix, $prefixMatches);
        }

        if (!$prefixMatches) {
            throw new InvalidPaymentRequestException('not a proper lightning payment request');
        }

        $bech32Prefix = $prefixMatches[1];
        $coinNetwork = $this->getNetworkFromPrefix($bech32Prefix);

        // parse the value from hrp
        $value = $prefixMatches[2] ?? null;
        if ($value) {
            $divisor = $prefixMatches[3];

            try {
                $satoshis = (int) $this->hrpToSat($value.$divisor);
            } catch (\Throwable $exception) {
                $satoshis = 0;
                $removeSatoshis = true;
            }

            $milliSatoshis = (int) $this->hrpToMillisat($value.$divisor);
        } else {
            $satoshis = null;
            $milliSatoshis = null;
        }

        // reminder: left padded 0 bits, parse the timestamp
        $timestamp = $this->wordsToIntBE(\array_slice($words, 0, 7));
        $timestampString = date(\DateTime::ATOM, $timestamp);
        $words = \array_slice($words, 7); // trim off the left 7 words

        // parse the tags from the available words
        $tags = $this->parseTagsFromWords($words, $coinNetwork);

        if ($this->tagsContainItem($tags, $this->tagNames[6])) {
            $timeExpireDate = $timestamp + $this->tagsItems($tags, $this->tagNames[6]);
        } else {
            // Default is 3600 (1 hour) if not specified.
            $timeExpireDate = $timestamp + 3600;
        }

        // wordsToIntBE() keeps both terms within PHP_INT_MAX, but their sum can
        // still overflow to a float (a TypeError in date()), and an expiry past
        // the year 9999 gets a five-digit year that DateTime cannot parse back in
        // the denormalizer. Neither is a usable invoice, so reject it here.
        if (!\is_int($timeExpireDate) || $timeExpireDate > self::MAX_EXPIRY_TIMESTAMP) {
            throw new InvalidPaymentRequestException('expiry time is out of range');
        }

        $timeExpireDateString = date(\DateTime::ATOM, $timeExpireDate);

        $toSign = Buffertools::concat(
            new Buffer($prefix),
            $this->wordsToBuffer($wordsWithoutSignature, false),
        );

        $payReqHash = Hash::sha256($toSign);
        $sigPubkey = $this->extractVerifyPublicKey($recoveryID, $signatureBuffer, $payReqHash, $tags);

        $finalResult = [
            'prefix' => $prefix,
            'network' => $coinNetwork,
            'satoshis' => $satoshis,
            'milli_satoshis' => $milliSatoshis,
            'timestamp' => $timestamp,
            'timestamp_string' => $timestampString,
            'payee_node_key' => $sigPubkey->getHex(),
            'signature' => $signatureBuffer->getHex(),
            'recovery_flag' => $recoveryID,
            'tags' => $tags,
            '_payment_request_hash' => $payReqHash->getHex(),
            '_message_to_sign' => $toSign->getHex(),
        ];

        if ($removeSatoshis ?? false) {
            unset($finalResult['satoshis']);
        }

        // Always present since the default expiry from PR #12; the spec's default
        // is 3600 seconds when there is no `x` field.
        $finalResult['expiry_timestamp'] = $timeExpireDate;
        $finalResult['expiry_datetime'] = $timeExpireDateString;

        return $finalResult;
    }

    protected function initializeTagParsers(): void
    {
        $this->tagParsers[1] = [$this, 'wordsToHex'];
        $this->tagParsers[16] = [$this, 'wordsToHex'];
        $this->tagParsers[13] = [$this, 'wordsToUtf8'];
        $this->tagParsers[19] = [$this, 'wordsToHex'];
        $this->tagParsers[23] = [$this, 'wordsToHex'];
        $this->tagParsers[6] = [$this, 'wordsToIntBE']; // default: 3600 (1 hour)
        $this->tagParsers[24] = [$this, 'wordsToIntBE']; // default: 9
        $this->tagParsers[9] = [$this, 'fallbackAddressParser'];
        $this->tagParsers[3] = [$this, 'routingInfoParser']; // for extra routing info (private etc.)
    }

    protected function wordsToBuffer(array $words, bool $trim = true): BufferInterface
    {
        $buffer = Buffer::hex(bin2hex(implode('', array_map('chr', $this->convert($words, 5, 8)))));

        if ($trim && 0 !== \count($words) * 5 % 8) {
            $buffer = $buffer->slice(0, -1);
        }

        return $buffer;
    }

    protected function getNetworkFromPrefix(string $bech32Prefix): NetworkInterface
    {
        switch ($bech32Prefix) {
            case 'bc':
                return new BitcoinMainnet();

            case 'tb':
                return new BitcoinTestnet();

            default:
                throw new UnknownNetworkVersionException('unknown network for invoice');
        }
    }

    protected function wordsToIntBE(array $words): int
    {
        // Shift in five bits per word instead of summing powers of 32: from the
        // 13th word on, 32 ** $index is a float, which turned the result into a
        // float and the return type into a TypeError, even for leading zeros.
        // The spec puts no upper bound on `x` or `c`, so check for overflow.
        $total = 0;
        foreach ($words as $word) {
            if ($total > (PHP_INT_MAX >> 5)) {
                throw new InvalidPaymentRequestException('integer field is too large');
            }

            $total = ($total << 5) | $word;
        }

        return $total;
    }

    protected function parseTagsFromWords(array $words, NetworkInterface $coinNetwork): array
    {
        $tags = [];
        while (!empty($words)) {
            try {
                $tagCode = (string) $words[0];
                $tagName = $this->tagNames[$tagCode] ?? self::NAME_UNKNOWN_TAG;
                $parser = $this->tagParsers[$tagCode] ?? $this->getUnknownParser($tagCode);
                $words = \array_slice($words, 1);

                $tagLength = $this->wordsToIntBE(\array_slice($words, 0, 2));
                $words = \array_slice($words, 2);

                $tagWords = \array_slice($words, 0, $tagLength);
                $words = \array_slice($words, $tagLength);

                if (52 !== $tagLength && \in_array((int) $tagCode, [1, 23, 16], true)) {
                    // MUST skip p, h, s fields that do NOT have data_lengths of 52.
                    continue;
                }

                if (53 !== $tagLength && 19 === (int) $tagCode) {
                    // MUST skip n fields that do NOT have data_length 53.
                    continue;
                }

                $tags[] = ['tag_name' => $tagName, 'data' => $parser($tagWords, $coinNetwork)];
            } catch (UnknownFallbackAddressVersionException $exception) {
                // allowed: reader MUST skip over an f field with unknown version
            }
        }

        return $tags;
    }

    protected function getUnknownParser(string $tagCode): \Closure
    {
        return static function ($words) use ($tagCode) {
            return [
                'tag_code' => (int) $tagCode,
                'words' => encode('unknown', $words),
            ];
        };
    }

    protected function tagsContainItem(array $tags, string $tagName): bool
    {
        return null !== $this->tagsItems($tags, $tagName);
    }

    protected function tagsItems(array $tags, string $tagName)
    {
        foreach ($tags as $tag) {
            if ($tagName === $tag['tag_name']) {
                return $tag['data'] ?? null;
            }
        }

        return null;
    }

    protected function extractVerifyPublicKey(
        int $recoveryID,
        BufferInterface $signatureBuffer,
        BufferInterface $payReqHash,
        array $tags
    ): PublicKeyInterface {
        try {
            // rebuild the signature buffer in a way bit-wasp accepts and knows it (flag+sig), add 27 + 4 (compressed sig).
            $reformattedSignatureBuffer = Buffertools::concat(Buffer::int($recoveryID + 27 + 4), $signatureBuffer);
            $compactSignature = (new CompactSignatureSerializer($this->ecAdapter))->parse($reformattedSignatureBuffer);
            $sigPubkey = $this->ecAdapter->recover($payReqHash, $compactSignature);
        } catch (\Throwable $exception) {
            throw new UnrecoverableSignatureException('unable to recover signature from signed message', $exception->getCode(), $exception);
        }

        if (
            $this->tagsContainItem($tags, $this->tagNames[19])
            && $this->tagsItems(
                $tags,
                $this->tagNames[19]
            ) !== $sigPubkey->getHex()
        ) {
            throw new SignatureDoesNotMatchPayeePubkeyDecodeException('lightning payment request signature pubkey does not match payee pubkey');
        }

        return $sigPubkey;
    }

    protected function wordsToHex(array $words): string
    {
        return $this->wordsToBuffer($words)->getHex();
    }

    protected function wordsToUtf8(array $words): string
    {
        return mb_convert_encoding($this->wordsToBuffer($words)->getBinary(), 'utf-8');
    }

    protected function routingInfoParser(array $words): array
    {
        $routes = [];
        $routesBuffer = $this->wordsToBuffer($words);

        // Each hop is exactly 51 bytes. A partial hop used to surface as a plain
        // \Exception from bitwasp/buffertools when slicing past the end.
        if (0 !== $routesBuffer->getSize() % 51) {
            throw new InvalidPaymentRequestException('routing info (r) field has an invalid length');
        }

        while ($routesBuffer->getSize() > 0) {
            $pubKey = $routesBuffer->slice(0, 33)->getHex(); // 33 bytes
            $shortChannelId = $routesBuffer->slice(33, 8)->getHex(); // 8 bytes
            $feeBaseMSats = (int) $routesBuffer->slice(41, 4)->getInt(); // 4 bytes
            $feeProportionalMillionths = (int) $routesBuffer->slice(45, 4)->getInt(); // 4 bytes
            $cltvExpiryDelta = (int) $routesBuffer->slice(49, 2)->getInt(); // 2 bytes

            $routesBuffer = $routesBuffer->slice(51);

            $routes[] = [
                'pubkey' => $pubKey,
                'short_channel_id' => $shortChannelId,
                'fee_base_msat' => $feeBaseMSats,
                'fee_proportional_millionths' => $feeProportionalMillionths,
                'cltv_expiry_delta' => $cltvExpiryDelta,
            ];
        }

        return $routes;
    }

    protected function fallbackAddressParser(array $words, NetworkInterface $network): array
    {
        // An empty `f` field has no version. Reading $words[0] anyway gave null,
        // which the loose switch below matched against `case 0`.
        if ([] === $words) {
            throw new InvalidPaymentRequestException('fallback address (f) field is empty');
        }

        $version = $words[0];
        $words = \array_slice($words, 1);
        $addressHash = $this->wordsToBuffer($words);

        try {
            $address = $this->fallbackAddressFromHash($version, $addressHash, $network);
        } catch (UnknownFallbackAddressVersionException $exception) {
            throw $exception;
        } catch (\RuntimeException $exception) {
            // bitwasp/bitcoin rejects a hash of the wrong length for its version
            // with a plain \RuntimeException; give it the library's own type.
            throw new InvalidPaymentRequestException('fallback address (f) field is invalid: '.$exception->getMessage(), 0, $exception);
        }

        return [
            'code' => $version,
            'address' => $address,
            'address_hash' => $addressHash->getHex(),
        ];
    }

    private function fallbackAddressFromHash(int $version, BufferInterface $addressHash, NetworkInterface $network): string
    {
        switch ($version) {
            case 17:
                return (new PayToPubKeyHashAddress($addressHash))->getAddress($network);

            case 18:
                return (new ScriptHashAddress($addressHash))->getAddress($network);

            case 0:
                return (new SegwitAddress(WitnessProgram::v0($addressHash)))->getAddress($network);

            default:
                throw new UnknownFallbackAddressVersionException('unknown fallback address version ('.$version.') encountered while parsing');
        }
    }
}
