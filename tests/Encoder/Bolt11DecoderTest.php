<?php

declare(strict_types=1);

namespace Tests\Jorijn\Bitcoin\Bolt11\Encoder;

use BitWasp\Bitcoin\Bitcoin;
use Jorijn\Bitcoin\Bolt11\Encoder\Bolt11Decoder;
use PHPUnit\Framework\TestCase;

/**
 * @coversDefaultClass \Jorijn\Bitcoin\Bolt11\Encoder\Bolt11Decoder
 * @covers ::__construct
 */
class Bolt11DecoderTest extends TestCase
{
    /** @var Bolt11Decoder */
    protected $decoder;

    /**
     * These examples were taken from GitHub.
     *
     * @see https://github.com/lightningnetwork/lightning-rfc/blob/master/11-payment-encoding.md#examples
     *
     * @return array[]
     */
    public function providerOfSuccessScenarios(): array
    {
        return [
            'Please make a donation of any amount using payment_hash 0001020304050607080900010203040506070809000102030405060708090102 to me @03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad' => [
                'lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq8rkx3yf5tcsyz3d73gafnh3cax9rn449d9p5uxz9ezhhypd0elx87sjle52x86fux2ypatgddc6k63n7erqz25le42c4u4ecky03ylcqca784w',
                [
                    'prefix' => 'lnbc',
                    'timestamp' => 1496314658,
                    'signature' => '38ec6891345e204145be8a3a99de38e98a39d6a569434e1845c8af7205afcfcc7f425fcd1463e93c32881ead0d6e356d467ec8c02553f9aab15e5738b11f127f',
                    'tags' => [
                        'payment_hash' => '0001020304050607080900010203040506070809000102030405060708090102',
                        'description' => 'Please consider supporting this project',
                    ],
                    'recoveryFlag' => 0,
                    'satoshis' => null,
                    'payeeNodeKey' => '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad',
                    '_payReqHash' => 'c3d4e83f646fa79a393d75277b1d858db1d1f7ab7137dcb7835db2ecd518e1c9',
                    '_toSign' => '6c6e62630b25fe64410d00004080c1014181c20240004080c1014181c20240004080c1014181c202404081a1fa83632b0b9b29031b7b739b4b232b91039bab83837b93a34b733903a3434b990383937b532b1ba0',
                ],
            ],
            'Please send $3 for a cup of coffee to the same peer, within one minute' => [
                'lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpuaztrnwngzn3kdzw5hydlzf03qdgm2hdq27cqv3agm2awhz5se903vruatfhq77w3ls4evs3ch9zw97j25emudupq63nyw24cg27h2rspfj9srp',
                [
                    '_payReqHash' => '3c3aa1c9fba327079f59e744d328700c6f3f6f418ce4db4037b0867ae6f46425',
                    '_toSign' => '6c6e626332353030750b25fe64410d00004080c1014181c20240004080c1014181c20240004080c1014181c202404081a0a189031bab81031b7b33332b2818020f',
                    'prefix' => 'lnbc2500u',
                    'millisatoshis' => 250000000,
                    'payeeNodeKey' => '0307bfecdf775fe29aafe6446e223d9068aa27e267c74f1923223483ba7e654175',
                    'recoveryFlag' => 1,
                    'satoshis' => 250000,
                    'signature' => 'e89639ba6814e36689d4b91bf125f10351b55da057b00647a8dabaeb8a90c95f160f9d5a6e0f79d1fc2b964238b944e2fa4aa677c6f020d466472ab842bd750e',
                    'tags' => [
                        'payment_hash' => '0001020304050607080900010203040506070809000102030405060708090102',
                        'description' => '1 cup coffee',
                        'expire_time' => 60,
                    ],
                    'timeExpireDate' => 1496314718,
                    'timeExpireDateString' => '2017-06-01T10:58:38+00:00',
                    'timestamp' => 1496314658,
                    'timestampString' => '2017-06-01T10:57:38+00:00',
                ],
            ],
            'Please send 0.0025 BTC for a cup of nonsense (ナンセンス 1杯) to the same peer, within one minute' => [
                'lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrny',
                [
                    '_payReqHash' => '9d96ed9ddd522deeee4884219ead16a1b5269015b0bb9bd17f553fb224656cd8',
                    '_toSign' => '6c6e626332353030750b25fe64410d00004080c1014181c20240004080c1014181c20240004080c1014181c202404081a1071c1c571c1d9f1c15df1c1d9f1c15c9018f34ed798020',
                    'prefix' => 'lnbc2500u',
                    'millisatoshis' => 250000000,
                    'payeeNodeKey' => '0207f0a34ef228239f9d5fa92c24e5bbaabf25ea0183f5b482651c09db2e9ec6b1',
                    'recoveryFlag' => 0,
                    'satoshis' => 250000,
                    'signature' => '259f04511e7ef2aa77f6ff04d51b4ae9209504843e5ab9672ce32a153681f687515b73ce57ee309db588a10eb8e41b5a2d2bc17144ddf398033faa49ffe95ae6',
                    'tags' => [
                        'payment_hash' => '0001020304050607080900010203040506070809000102030405060708090102',
                        'description' => 'ナンセンス 1杯',
                        'expire_time' => 60,
                    ],
                    'timeExpireDate' => 1496314718,
                    'timeExpireDateString' => '2017-06-01T10:58:38+00:00',
                    'timestamp' => 1496314658,
                    'timestampString' => '2017-06-01T10:57:38+00:00',
                ],
            ],
            'Now send $24 for an entire list of things (hashed)' => [
                'lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqscc6gd6ql3jrc5yzme8v4ntcewwz5cnw92tz0pc8qcuufvq7khhr8wpald05e92xw006sq94mg8v2ndf4sefvf9sygkshp5zfem29trqq2yxxz7',
                [
                    'payeeNodeKey' => '021fe79f22a93c57805f621304a2b0d834805ed6d4cedceaf3fad0f89b72ef9906',
                    'recoveryFlag' => 0,
                    'satoshis' => 2000000,
                    'signature' => 'c63486e81f8c878a105bc9d959af1973854c4dc552c4f0e0e0c7389603d6bdc67707bf6be992a8ce7bf50016bb41d8a9b5358652c4960445a170d049ced4558c',
                    'tags' => [
                        'payment_hash' => '0001020304050607080900010203040506070809000102030405060708090102',
                        'purpose_commit_hash' => '3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1',
                    ],
                ],
            ],
            'The same, on testnet, with a fallback address mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP' => [
                'lntb20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfpp3x9et2e20v6pu37c5d9vax37wxq72un98kmzzhznpurw9sgl2v0nklu2g4d0keph5t7tj9tcqd8rexnd07ux4uv2cjvcqwaxgj7v4uwn5wmypjd5n69z2xm3xgksg28nwht7f6zspwp3f9t',
                [
                    'payeeNodeKey' => '03288e6c22381c44e425a1611197b0f3164cc7aeb719844cebd6f239731f7f51df',
                    'recoveryFlag' => 1,
                    'satoshis' => 2000000,
                    'signature' => 'b6c42b8a61e0dc5823ea63e76ff148ab5f6c86f45f9722af0069c7934daff70d5e315893300774c897995e3a7476c8193693d144a36e2645a0851e6ebafc9d0a',
                    'tags' => [
                        'payment_hash' => '0001020304050607080900010203040506070809000102030405060708090102',
                        'purpose_commit_hash' => '3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1',
                        'fallback_address' => [
                            'code' => 17,
                            'address' => 'xx', // FIXME: 'mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP',
                            'addressHash' => '3172b5654f6683c8fb146959d347ce303cae4ca7',
                        ],
                    ],
                    'network' => [
                        'chain' => 'testnet',
                    ],
                ],
            ],
            // TODO: add more
        ];
    }

    /**
     * These examples were taken from GitHub.
     *
     * @see https://github.com/lightningnetwork/lightning-rfc/blob/master/11-payment-encoding.md#examples-of-invalid-invoices
     */
    public function providerOfInvalidScenarios(): array
    {
        // TODO
        return [];
    }

    /**
     * TODO: expand coverage annotation.
     *
     * @covers ::decode
     * @covers ::initializeTagParsers
     * @covers ::wordsToBuffer
     * @covers ::convert
     * @covers ::hrpToSat
     * @covers ::hrpToMillisat
     * @covers ::wordsToIntBE
     * @covers ::getUnknownParser
     * @covers ::tagsContainItem
     * @covers ::tagsItems
     * @covers ::wordsToHex
     * @covers ::wordsToUtf8
     * @covers ::featureParser TODO
     * @covers ::routingInfoParser
     * @covers ::fallbackAddressParser
     * @dataProvider providerOfSuccessScenarios
     */
    public function testSuccessScenarios(string $invoice, array $results): void
    {
        $result = $this->decoder->decode($invoice);

        foreach ($results as $expectedKey => $expectedValue) {
            self::assertArrayHasKey($expectedKey, $result);

            if ('tags' === $expectedKey) {
                foreach ($expectedValue as $expectedTag => $expectedTagValue) {
                    $found = false;
                    foreach ($result['tags'] as $tag) {
                        if ($tag['tagName'] === $expectedTag) {
                            $found = true;
                            self::assertSame(
                                $expectedTagValue,
                                $tag['data'],
                                sprintf('tag "%s" does not match expected value', $expectedTag)
                            );
                        }
                    }

                    self::assertTrue($found);
                }
            } elseif (is_array($expectedValue)) {
                foreach ($expectedValue as $expectedSubKey => $expectedSubValue) {
                    self::assertArrayHasKey($expectedSubKey, $expectedValue);
                    self::assertSame(
                        $expectedSubValue,
                        $expectedValue[$expectedSubKey],
                        sprintf('"%s.%s" does not match expected value', $expectedKey, $expectedSubKey)
                    );
                }
            } else {
                self::assertSame(
                    $expectedValue,
                    $result[$expectedKey],
                    sprintf('"%s" does not match expected value', $expectedKey)
                );
            }
        }
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->decoder = new Bolt11Decoder(Bitcoin::getEcAdapter());
    }
}
