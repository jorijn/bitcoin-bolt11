<?php

declare(strict_types=1);

namespace Jorijn\Bitcoin\Bolt11\Encoder;

use function BitWasp\Bech32\decodeRaw;
use function BitWasp\Bech32\encode;
use BitWasp\Bitcoin\Bitcoin;
use BitWasp\Bitcoin\Crypto\EcAdapter\Adapter\EcAdapterInterface;
use BitWasp\Bitcoin\Crypto\EcAdapter\Impl\PhpEcc\Serializer\Signature\CompactSignatureSerializer;
use BitWasp\Bitcoin\Crypto\Hash;
use BitWasp\Buffertools\Buffer;
use BitWasp\Buffertools\BufferInterface;
use BitWasp\Buffertools\Buffertools;
use Jorijn\Bitcoin\Bolt11\Exception\Bolt11DecodeException;
use Jorijn\Bitcoin\Bolt11\Exception\SignatureDoesNotMatchPayeePubkeyDecodeException;

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
class Bolt11Decoder
{
    public const DEFAULT_NETWORK = [
        'chain' => 'mainnet',
        'bech32' => 'bc',
        'pubKeyHash' => 0x00,
        'scriptHash' => 0x05,
        'validWitnessVersions' => [0],
    ];

    public const TEST_NETWORK = [
        'chain' => 'testnet',
        'bech32' => 'tb',
        'pubKeyHash' => 0x6f,
        'scriptHash' => 0xc4,
        'validWitnessVersions' => [0],
    ];

    public const SIM_NETWORK = [
        'chain' => 'simnet',
        'bech32' => 'sb',
        'pubKeyHash' => 0x3f,
        'scriptHash' => 0x7b,
        'validWitnessVersions' => [0],
    ];

    public const DIVISORS = [
        'm' => '1000.0000000000',
        'u' => '1000000.0000000000',
        'n' => '1000000000.0000000000',
        'p' => '1000000000000.0000000000',
    ];

    public const MAX_MILLISATS = '2100000000000000000.0000000000';
    public const MILLISATS_PER_BTC = '100000000000.0000000000';
    public const MILLISATS_PER_MILLIBTC = '100000000.0000000000';
    public const MILLISATS_PER_MICROBTC = '100000.0000000000';
    public const MILLISATS_PER_NANOBTC = '100.0000000000';
    public const PICOBTC_PER_MILLISATS = '10.0000000000';
    public const NAME_UNKNOWN_TAG = 'unknownTag';

    public const TAG_CODES = [
        'payment_hash' => 1,
        'description' => 13,
        'payee_node_key' => 19,
        'purpose_commit_hash' => 23,
        'expire_time' => 6,
        'min_final_cltv_expiry' => 24,
        'fallback_address' => 9,
        'routing_info' => 3,
        'secret' => 16,
//        'features' => 5, TODO
    ];

    /** @var string[] */
    protected $tagNames = [];
    /** @var \Closure[] */
    protected $tagParsers = [];
    /** @var EcAdapterInterface */
    protected $ecAdapter;

    public function __construct(EcAdapterInterface $ecAdapter = null)
    {
        $this->ecAdapter = $ecAdapter ?? Bitcoin::getEcAdapter();
        $this->tagNames = array_flip(self::TAG_CODES);
        $this->initializeTagParsers();
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
//        $this->tagParsers[5] = [$this, 'featureParser']; // TODO
    }

    public function decode(string $paymentRequest)
    {
        [$prefix, $words] = decodeRaw($paymentRequest);

        if (0 !== strpos($prefix, 'ln')) {
            throw new Bolt11DecodeException('data does not appear to be a bolt11 invoice');
        }

        // signature is always 104 words on the end
        // cutting off at the beginning helps since there's no way to tell
        // ahead of time how many tags there are.
        $signatureWords = array_slice($words, -104);

        // grabbing a copy of the words for later, words will be sliced as we parse.
        $wordsWithoutSignature = array_slice($words, 0, -104);
        $words = array_slice($words, 0, -104);
        $signatureBuffer = $this->wordsToBuffer($signatureWords);
        $recoveryID = (int) $signatureBuffer->slice(-1)->getInt();

        // get remaining signature buffer after extracting recovery flag
        $signatureBuffer = $signatureBuffer->slice(0, -1);
        if (!(in_array($recoveryID, [0, 1, 2, 3], true)) || 64 !== $signatureBuffer->getSize()) {
            throw new Bolt11DecodeException('signature is missing or incorrect');
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
            throw new Bolt11DecodeException('not a proper lightning payment request');
        }

        $bech32Prefix = $prefixMatches[1];
        switch ($bech32Prefix) {
            case self::DEFAULT_NETWORK['bech32']:
                $coinNetwork = self::DEFAULT_NETWORK;
                break;
            case self::TEST_NETWORK['bech32']:
                $coinNetwork = self::TEST_NETWORK;
                break;
            case self::SIM_NETWORK['bech32']:
                $coinNetwork = self::SIM_NETWORK;
                break;
            default:
                throw new Bolt11DecodeException('unknown network for invoice');
        }

        $value = $prefixMatches[2] ?? null;
        if ($value) {
            $divisor = $prefixMatches[3];

            try {
                $satoshis = (int) ($this->hrpToSat($value.$divisor));
            } catch (\Throwable $exception) {
                $satoshis = 0;
                $removeSatoshis = true;
            }

            $millisatoshis = (int) $this->hrpToMillisat($value.$divisor);
        } else {
            $satoshis = null;
            $millisatoshis = null;
        }

        // reminder: left padded 0 bits
        $timestamp = $this->wordsToIntBE(array_slice($words, 0, 7));
        $timestampString = date(\DateTime::ATOM, $timestamp);

        $words = array_slice($words, 7); // trim off the left 7 words

        $tags = [];
        while (!empty($words)) {
            $tagCode = (string) $words[0];
            $tagName = $this->tagNames[$tagCode] ?? self::NAME_UNKNOWN_TAG;
            $parser = $this->tagParsers[$tagCode] ?? $this->getUnknownParser($tagCode);
            $words = array_slice($words, 1);

            $tagLength = $this->wordsToIntBE(array_slice($words, 0, 2));
            $words = array_slice($words, 2);

            $tagWords = array_slice($words, 0, $tagLength);
            $words = array_slice($words, $tagLength);

            $tags[] = ['tagName' => $tagName, 'data' => $parser($tagWords, $coinNetwork)];
        }

        $timeExpireDate = $timeExpireDateString = null;
        if ($this->tagsContainItem($tags, $this->tagNames[6])) {
            $timeExpireDate = $timestamp + $this->tagsItems($tags, $this->tagNames[6]);
            $timeExpireDateString = date(\DateTime::ATOM, $timeExpireDate);
        }

        $toSign = Buffertools::concat(
            new Buffer($prefix),
            $this->wordsToBuffer($wordsWithoutSignature),
        );

        $payReqHash = Hash::sha256($toSign);

        // rebuild the signature buffer in a way bit-wasp accepts and knows it (flag+sig), add 27 + 4 (compressed sig).
        $reformattedSignatureBuffer = Buffertools::concat(Buffer::int($recoveryID + 27 + 4), $signatureBuffer);
        $compactSignature = (new CompactSignatureSerializer($this->ecAdapter))->parse($reformattedSignatureBuffer);
        $sigPubkey = $this->ecAdapter->recover($payReqHash, $compactSignature);

        if (
            $this->tagsContainItem($tags, $this->tagNames[19])
            && $this->tagsItems(
                $tags,
                $this->tagNames[19]
            ) !== $sigPubkey->getHex()
        ) {
            throw new SignatureDoesNotMatchPayeePubkeyDecodeException('lightning payment request signature pubkey does not match payee pubkey');
        }

        $finalResult = [
            'paymentRequest' => $paymentRequest,
            'complete' => true,
            'prefix' => $prefix,
            'wordsTemp' => encode('temp', $wordsWithoutSignature + $signatureWords),
            'network' => $coinNetwork,
            'satoshis' => $satoshis,
            'millisatoshis' => $millisatoshis,
            'timestamp' => $timestamp,
            'timestampString' => $timestampString,
            'payeeNodeKey' => $sigPubkey->getHex(),
            'signature' => $signatureBuffer->getHex(),
            'recoveryFlag' => $recoveryID,
            'tags' => $tags,
            '_payReqHash' => $payReqHash->getHex(),
            '_toSign' => $toSign->getHex(),
        ];

        if ($removeSatoshis ?? false) {
            unset($finalResult['satoshis']);
        }

        if (null !== $timeExpireDate) {
            $finalResult['timeExpireDate'] = $timeExpireDate;
            $finalResult['timeExpireDateString'] = $timeExpireDateString;
        }

        ksort($finalResult);

        return $finalResult;
    }

    protected function wordsToBuffer(array $words, bool $trim = true): BufferInterface
    {
        $buffer = Buffer::hex(bin2hex(implode(array_map('chr', $this->convert($words, 5, 8)))));

        if ($trim && 0 !== count($words) * 5 % 8) {
            $buffer = $buffer->slice(0, -1);
        }

        return $buffer;
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

        if ('0.0000000000' === bcmod($milliSatoshis, '1000.0000000000')) {
            throw new Bolt11DecodeException('amount is outside of valid range');
        }

        return bcdiv($milliSatoshis, '1000.0000000000');
    }

    public function hrpToMillisat(string $hrpString): string
    {
        $divisor = null;

        if (preg_match('/^[munp]$/', substr($hrpString, -1))) {
            $divisor = substr($hrpString, -1);
            $value = substr($hrpString, 0, -1);
        } elseif (preg_match('/^[^munp0-9]$/', substr($hrpString, -1))) {
            throw new Bolt11DecodeException('not a valid multiplier for the amount');
        } else {
            $value = $hrpString;
        }

        if (!preg_match('/^\d+$/', $value)) {
            throw new Bolt11DecodeException('not a valid human readable amount');
        }

        $valueBN = bcmul($value, '1', 10);
        $milliSatoshisBN = $divisor
            ? bcdiv(bcmul($valueBN, self::MILLISATS_PER_BTC), self::DIVISORS[$divisor])
            : bcmul($valueBN, self::MILLISATS_PER_BTC);

        if ((('p' === $divisor && '0.0000000000' === !bcmod($valueBN, '10.0000000000')) ||
            1 === bccomp($milliSatoshisBN, self::MAX_MILLISATS))) {
            throw new Bolt11DecodeException('amount is outside valid range');
        }

        return $milliSatoshisBN;
    }

    protected function wordsToIntBE(array $words): int
    {
        $total = 0;
        foreach (array_reverse($words) as $index => $item) {
            $total += $item * (32 ** $index);
        }

        return $total;
    }

    protected function getUnknownParser(string $tagCode): \Closure
    {
        return static function ($words) use ($tagCode) {
            return [
                'tagCode' => (int) $tagCode,
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
            if ($tagName === $tag['tagName']) {
                return $tag['data'] ?? null;
            }
        }

        return null;
    }

    protected function wordsToHex(array $words): string
    {
        return $this->wordsToBuffer($words)->getHex();
    }

    protected function wordsToUtf8(array $words): string
    {
        return mb_convert_encoding($this->wordsToBuffer($words)->getBinary(), 'utf-8');
    }

    protected function featureParser(array $words): array
    {
        $features = [];
        $featuresBuffer = $this->wordsToBuffer($words);

        throw new \Exception('incomplete method');
    }

    protected function routingInfoParser(array $words): array
    {
        $routes = [];
        $routesBuffer = $this->wordsToBuffer($words);

        while ($routesBuffer->getSize() > 0) {
            $pubKey = $routesBuffer->slice(0, 33)->getHex(); // 33 bytes
            $shortChannelId = $routesBuffer->slice(33, 8)->getHex(); // 8 bytes
            $feeBaseMSats = $routesBuffer->slice(41, 4)->getInt(); // 4 bytes
            $feeProportionalMillionths = $routesBuffer->slice(45, 4)->getInt(); // 4 bytes
            $cltvExpiryDelta = $routesBuffer->slice(49, 2)->getHex(); // 2 bytes

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

    protected function fallbackAddressParser(array $words): array
    {
        $version = $words[0];
        $words = array_slice($words, 1);
        $addressHash = $this->wordsToBuffer($words);

        switch ($version) {
            case 17:
                $address = 'xx'; // FIXME: bitcoinjsAddress.toBase58Check(addressHash, network.pubKeyHash)
                break;
            case 18:
                $address = 'xx'; // FIXME:bitcoinjsAddress.toBase58Check(addressHash, network.scriptHash)
                break;
            case 0:
                $address = 'xx'; // FIXME:bitcoinjsAddress.toBech32(addressHash, version, network.bech32)
                break;
            default:
                throw new Bolt11DecodeException('unknown fallback address version encountered while parsing');
        }

        return [
            'code' => $version,
            'address' => $address,
            'addressHash' => $addressHash->getHex(),
        ];
    }
}
