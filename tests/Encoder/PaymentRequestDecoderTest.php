<?php

declare(strict_types=1);

namespace Tests\Jorijn\Bitcoin\Bolt11\Encoder;

use BitWasp\Bitcoin\Bitcoin;
use Jorijn\Bitcoin\Bolt11\Encoder\PaymentRequestDecoder;
use Jorijn\Bitcoin\Bolt11\Exception\InvalidAmountException;
use Jorijn\Bitcoin\Bolt11\Exception\SignatureIncorrectOrMissingException;
use Jorijn\Bitcoin\Bolt11\Exception\UnableToDecodeBech32Exception;
use Jorijn\Bitcoin\Bolt11\Exception\UnrecoverableSignatureException;
use PHPUnit\Framework\TestCase;

/**
 * @coversDefaultClass \Jorijn\Bitcoin\Bolt11\Encoder\PaymentRequestDecoder
 * @covers ::__construct
 *
 * @internal
 */
final class PaymentRequestDecoderTest extends TestCase
{
    /** @var PaymentRequestDecoder */
    protected $decoder;

    protected function setUp(): void
    {
        parent::setUp();

        $this->decoder = new PaymentRequestDecoder(Bitcoin::getEcAdapter());
    }

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
                    'recovery_flag' => 0,
                    'satoshis' => null,
                    'payee_node_key' => '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad',
                    '_payment_request_hash' => 'c3d4e83f646fa79a393d75277b1d858db1d1f7ab7137dcb7835db2ecd518e1c9',
                    '_message_to_sign' => '6c6e62630b25fe64410d00004080c1014181c20240004080c1014181c20240004080c1014181c202404081a1fa83632b0b9b29031b7b739b4b232b91039bab83837b93a34b733903a3434b990383937b532b1ba0',
                ],
            ],
            'Please send $3 for a cup of coffee to the same peer, within one minute' => [
                'lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpuaztrnwngzn3kdzw5hydlzf03qdgm2hdq27cqv3agm2awhz5se903vruatfhq77w3ls4evs3ch9zw97j25emudupq63nyw24cg27h2rspfj9srp',
                [
                    '_payment_request_hash' => '3cd6ef07744040556e01be64f68fd9e1565fb47d78c42308b1ee005aca5a0d86',
                    '_message_to_sign' => '6c6e626332353030750b25fe64410d00004080c1014181c20240004080c1014181c20240004080c1014181c202404081a0a189031bab81031b7b33332b2818020f',
                    'prefix' => 'lnbc2500u',
                    'milli_satoshis' => 250000000,
                    'payee_node_key' => '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad',
                    'recovery_flag' => 1,
                    'satoshis' => 250000,
                    'signature' => 'e89639ba6814e36689d4b91bf125f10351b55da057b00647a8dabaeb8a90c95f160f9d5a6e0f79d1fc2b964238b944e2fa4aa677c6f020d466472ab842bd750e',
                    'tags' => [
                        'payment_hash' => '0001020304050607080900010203040506070809000102030405060708090102',
                        'description' => '1 cup coffee',
                        'expire_time' => 60,
                    ],
                    'expiry_timestamp' => 1496314718,
                    'expiry_datetime' => '2017-06-01T10:58:38+00:00',
                    'timestamp' => 1496314658,
                    'timestamp_string' => '2017-06-01T10:57:38+00:00',
                ],
            ],
            'Please send 0.0025 BTC for a cup of nonsense (ナンセンス 1杯) to the same peer, within one minute' => [
                'lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrny',
                [
                    '_payment_request_hash' => '197a3061f4f333d86669b8054592222b488f3c657a9d3e74f34f586fb3e7931c',
                    '_message_to_sign' => '6c6e626332353030750b25fe64410d00004080c1014181c20240004080c1014181c20240004080c1014181c202404081a1071c1c571c1d9f1c15df1c1d9f1c15c9018f34ed798020',
                    'prefix' => 'lnbc2500u',
                    'milli_satoshis' => 250000000,
                    'payee_node_key' => '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad',
                    'recovery_flag' => 0,
                    'satoshis' => 250000,
                    'signature' => '259f04511e7ef2aa77f6ff04d51b4ae9209504843e5ab9672ce32a153681f687515b73ce57ee309db588a10eb8e41b5a2d2bc17144ddf398033faa49ffe95ae6',
                    'tags' => [
                        'payment_hash' => '0001020304050607080900010203040506070809000102030405060708090102',
                        'description' => 'ナンセンス 1杯',
                        'expire_time' => 60,
                    ],
                    'expiry_timestamp' => 1496314718,
                    'expiry_datetime' => '2017-06-01T10:58:38+00:00',
                    'timestamp' => 1496314658,
                    'timestamp_string' => '2017-06-01T10:57:38+00:00',
                ],
            ],
            'Now send $24 for an entire list of things (hashed)' => [
                'lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqscc6gd6ql3jrc5yzme8v4ntcewwz5cnw92tz0pc8qcuufvq7khhr8wpald05e92xw006sq94mg8v2ndf4sefvf9sygkshp5zfem29trqq2yxxz7',
                [
                    'payee_node_key' => '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad',
                    'recovery_flag' => 0,
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
                    'payee_node_key' => '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad',
                    'recovery_flag' => 1,
                    'satoshis' => 2000000,
                    'signature' => 'b6c42b8a61e0dc5823ea63e76ff148ab5f6c86f45f9722af0069c7934daff70d5e315893300774c897995e3a7476c8193693d144a36e2645a0851e6ebafc9d0a',
                    'tags' => [
                        'payment_hash' => '0001020304050607080900010203040506070809000102030405060708090102',
                        'purpose_commit_hash' => '3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1',
                        'fallback_address' => [
                            'code' => 17,
                            'address' => 'mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP',
                            'address_hash' => '3172b5654f6683c8fb146959d347ce303cae4ca7',
                        ],
                    ],
                    'network' => [
                        'chain' => 'testnet',
                    ],
                ],
            ],
            'On mainnet, with fallback address 1RustyRX2oai4EYYDpQGWvEL62BBGqN9T with extra routing info to go via nodes 029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255 then 039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255' => [
                'lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzqj9n4evl6mr5aj9f58zp6fyjzup6ywn3x6sk8akg5v4tgn2q8g4fhx05wf6juaxu9760yp46454gpg5mtzgerlzezqcqvjnhjh8z3g2qqdhhwkj',
                [
                    'payee_node_key' => '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad',
                    'satoshis' => 2000000,
                    'tags' => [
                        'fallback_address' => [
                            'code' => 17,
                            'address' => '1RustyRX2oai4EYYDpQGWvEL62BBGqN9T',
                            'address_hash' => '04b61f7dc1ea0dc99424464cc4064dc564d91e89',
                        ],
                        'routing_info' => [
                            [
                                'pubkey' => '029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255',
                                'short_channel_id' => '0102030405060708',
                                'fee_base_msat' => 1,
                                'fee_proportional_millionths' => 20,
                                'cltv_expiry_delta' => 3,
                            ],
                            [
                                'pubkey' => '039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255',
                                'short_channel_id' => '030405060708090a',
                                'fee_base_msat' => 2,
                                'fee_proportional_millionths' => 30,
                                'cltv_expiry_delta' => 4,
                            ],
                        ],
                    ],
                ],
            ],
            'On mainnet, with fallback (P2SH) address 3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX' => [
                'lnbc20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppj3a24vwu6r8ejrss3axul8rxldph2q7z9kmrgvr7xlaqm47apw3d48zm203kzcq357a4ls9al2ea73r8jcceyjtya6fu5wzzpe50zrge6ulk4nvjcpxlekvmxl6qcs9j3tz0469gq5g658y',
                [
                    'payee_node_key' => '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad',
                    'tags' => [
                        'fallback_address' => [
                            'code' => 18,
                            'address' => '3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX',
                            'address_hash' => '8f55563b9a19f321c211e9b9f38cdf686ea07845',
                        ],
                    ],
                ],
            ],
            'On mainnet, with fallback (P2WPKH) addressp bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4' => [
                'lnbc20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppqw508d6qejxtdg4y5r3zarvary0c5xw7kepvrhrm9s57hejg0p662ur5j5cr03890fa7k2pypgttmh4897d3raaq85a293e9jpuqwl0rnfuwzam7yr8e690nd2ypcq9hlkdwdvycqa0qza8',
                [
                    'payee_node_key' => '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad',
                    'tags' => [
                        'fallback_address' => [
                            'code' => 0,
                            'address' => 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
                            'address_hash' => '751e76e8199196d454941c45d1b3a323f1433bd6',
                        ],
                    ],
                ],
            ],
            'On mainnet, with fallback (P2WSH) address bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3' => [
                'lnbc20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfp4qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q28j0v3rwgy9pvjnd48ee2pl8xrpxysd5g44td63g6xcjcu003j3qe8878hluqlvl3km8rm92f5stamd3jw763n3hck0ct7p8wwj463cql26ava',
                [
                    'payee_node_key' => '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad',
                    'tags' => [
                        'fallback_address' => [
                            'code' => 0,
                            'address' => 'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3',
                            'address_hash' => '1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262',
                        ],
                    ],
                ],
            ],
            'Please send 0.00967878534 BTC for a list of items within one week, amount in pico-BTC' => [
                'lnbc9678785340p1pwmna7lpp5gc3xfm08u9qy06djf8dfflhugl6p7lgza6dsjxq454gxhj9t7a0sd8dgfkx7cmtwd68yetpd5s9xar0wfjn5gpc8qhrsdfq24f5ggrxdaezqsnvda3kkum5wfjkzmfqf3jkgem9wgsyuctwdus9xgrcyqcjcgpzgfskx6eqf9hzqnteypzxz7fzypfhg6trddjhygrcyqezcgpzfysywmm5ypxxjemgw3hxjmn8yptk7untd9hxwg3q2d6xjcmtv4ezq7pqxgsxzmnyyqcjqmt0wfjjq6t5v4khxxqyjw5qcqp2rzjq0gxwkzc8w6323m55m4jyxcjwmy7stt9hwkwe2qxmy8zpsgg7jcuwz87fcqqeuqqqyqqqqlgqqqqn3qq9qn07ytgrxxzad9hc4xt3mawjjt8znfv8xzscs7007v9gh9j569lencxa8xeujzkxs0uamak9aln6ez02uunw6rd2ht2sqe4hz8thcdagpleym0j',
                [
                    'milli_satoshis' => 967878534,
                    'payee_node_key' => '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad',
                    'satoshis' => 967878,
                    'tags' => [
                        'description' => 'Blockstream Store: 88.85 USD for Blockstream Ledger Nano S x 1, "Back In My Day" Sticker x 2, "I Got Lightning Working" Sticker x 2 and 1 more items',
                        'expire_time' => 604800,
                        'min_final_cltv_expiry' => 10,
                        'routing_info' => [
                            [
                                'pubkey' => '03d06758583bb5154774a6eb221b1276c9e82d65bbaceca806d90e20c108f4b1c7',
                                'short_channel_id' => '08fe4e000cf00001',
                                'fee_base_msat' => 1000,
                                'fee_proportional_millionths' => 2500,
                                'cltv_expiry_delta' => 40,
                            ],
                        ],
                    ],
                    'expiry_timestamp' => 1573073503,
                    'expiry_datetime' => '2019-11-06T20:51:43+00:00',
                    'timestamp' => 1572468703,
                    'timestamp_string' => '2019-10-30T20:51:43+00:00',
                ],
            ],
            'Please send $30 for coffee beans to the same peer, which supports features 9, 15 and 99, using secret 0x1111111111111111111111111111111111111111111111111111111111111111' => [
                'lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqpqsq67gye39hfg3zd8rgc80k32tvy9xk2xunwm5lzexnvpx6fd77en8qaq424dxgt56cag2dpt359k3ssyhetktkpqh24jqnjyw6uqd08sgptq44qu',
                [
                    'payee_node_key' => '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad',
                    'tags' => [
                        'secret' => '1111111111111111111111111111111111111111111111111111111111111111',
                        '5' => 'unknown1sqqqqqqqqqqqqqqqpqsqn2lwct',
                    ],
                ],
            ],
            'Same, but all upper case.' => [
                'LNBC25M1PVJLUEZPP5QQQSYQCYQ5RQWZQFQQQSYQCYQ5RQWZQFQQQSYQCYQ5RQWZQFQYPQDQ5VDHKVEN9V5SXYETPDEESSP5ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYGS9Q5SQQQQQQQQQQQQQQQPQSQ67GYE39HFG3ZD8RGC80K32TVY9XK2XUNWM5LZEXNVPX6FD77EN8QAQ424DXGT56CAG2DPT359K3SSYHETKTKPQH24JQNJYW6UQD08SGPTQ44QU',
                [
                    'payee_node_key' => '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad',
                    'tags' => [
                        'secret' => '1111111111111111111111111111111111111111111111111111111111111111',
                        '5' => 'unknown1sqqqqqqqqqqqqqqqpqsqn2lwct',
                    ],
                ],
            ],
            'Same, but including fields which must be ignored.' => [
                'lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqpqsq2qrqqqfppnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqppnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpp4qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhpnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhp4qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqspnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsp4qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqnp5qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqnpkqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq2jxxfsnucm4jf4zwtznpaxphce606fvhvje5x7d4gw7n73994hgs7nteqvenq8a4ml8aqtchv5d9pf7l558889hp4yyrqv6a7zpq9fgpskqhza',
                [
                    'satoshis' => 2500000,
                    'tags' => [
                        'description' => 'coffee beans',
                        'secret' => '1111111111111111111111111111111111111111111111111111111111111111',
                    ],
                ],
            ],
        ];
    }

    /**
     * These examples were taken from GitHub.
     *
     * @see https://github.com/lightningnetwork/lightning-rfc/blob/master/11-payment-encoding.md#examples-of-invalid-invoices
     */
    public function providerOfInvalidScenarios(): array
    {
        return [
            'Bech32 checksum is invalid.' => [
                'lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrnt',
                'Invalid bech32 checksum',
                UnableToDecodeBech32Exception::class,
            ],
            'Malformed bech32 string (no 1)' => [
                'pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrny',
                'Missing separator character',
                UnableToDecodeBech32Exception::class,
            ],
            'Malformed bech32 string (mixed case)' => [
                'LNBC2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrny',
                'Data contains mixture of higher/lower case characters',
                UnableToDecodeBech32Exception::class,
            ],
            'Signature is not recoverable.' => [
                'lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpuaxtrnwngzn3kdzw5hydlzf03qdgm2hdq27cqv3agm2awhz5se903vruatfhq77w3ls4evs3ch9zw97j25emudupq63nyw24cg27h2rspk28uwq',
                'unable to recover signature from signed message',
                UnrecoverableSignatureException::class,
            ],
            'String is too short.' => [
                'lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6na6hlh',
                'signature is missing or incorrect',
                SignatureIncorrectOrMissingException::class,
            ],
            'Invalid multiplier' => [
                'lnbc2500x1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpujr6jxr9gq9pv6g46y7d20jfkegkg4gljz2ea2a3m9lmvvr95tq2s0kvu70u3axgelz3kyvtp2ywwt0y8hkx2869zq5dll9nelr83zzqqpgl2zg',
                'not a valid multiplier for the amount',
                InvalidAmountException::class,
            ],
            'Invalid sub-millisatoshi precision.' => [
                'lnbc2500000001p1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu7hqtk93pkf7sw55rdv4k9z2vj050rxdr6za9ekfs3nlt5lr89jqpdmxsmlj9urqumg0h9wzpqecw7th56tdms40p2ny9q4ddvjsedzcplva53s',
                'amount is outside valid range',
                InvalidAmountException::class,
            ],
        ];
    }

    /**
     * @covers ::convert
     * @covers ::decode
     * @covers ::extractVerifyPublicKey
     * @covers ::fallbackAddressParser
     * @covers ::getNetworkFromPrefix
     * @covers ::getUnknownParser
     * @covers ::hrpToMillisat
     * @covers ::hrpToSat
     * @covers ::initializeTagParsers
     * @covers ::parseTagsFromWords
     * @covers ::routingInfoParser
     * @covers ::tagsContainItem
     * @covers ::tagsItems
     * @covers ::wordsToBuffer
     * @covers ::wordsToHex
     * @covers ::wordsToIntBE
     * @covers ::wordsToUtf8
     * @dataProvider providerOfSuccessScenarios
     */
    public function testSuccessScenarios(string $invoice, array $expectedResults): void
    {
        $result = $this->decoder->decode($invoice);

        foreach ($expectedResults as $expectedKey => $expectedValue) {
            static::assertArrayHasKey($expectedKey, $result);

            if ('tags' === $expectedKey) {
                foreach ($expectedValue as $expectedTag => $expectedTagValue) {
                    $found = false;
                    foreach ($result['tags'] as $tag) {
                        if ('unknownTag' === $tag['tag_name']) { // support testing unspported tags
                            $tag['tag_name'] = $tag['data']['tag_code'];
                            $tag['data'] = $tag['data']['words'];
                        }

                        if ($tag['tag_name'] === $expectedTag) {
                            $found = true;
                            static::assertSame(
                                $expectedTagValue,
                                $tag['data'],
                                sprintf('tag "%s" does not match expected value', $expectedTag)
                            );
                        }
                    }

                    static::assertTrue($found);
                }
            } elseif (\is_array($expectedValue)) {
                foreach ($expectedValue as $expectedSubKey => $expectedSubValue) {
                    static::assertArrayHasKey($expectedSubKey, $expectedValue);
                    static::assertSame(
                        $expectedSubValue,
                        $expectedValue[$expectedSubKey],
                        sprintf('"%s.%s" does not match expected value', $expectedKey, $expectedSubKey)
                    );
                }
            } else {
                static::assertSame(
                    $expectedValue,
                    $result[$expectedKey],
                    sprintf('"%s" does not match expected value', $expectedKey)
                );
            }
        }
    }

    /**
     * @covers ::convert
     * @covers ::decode
     * @covers ::extractVerifyPublicKey
     * @covers ::fallbackAddressParser
     * @covers ::getNetworkFromPrefix
     * @covers ::getUnknownParser
     * @covers ::hrpToMillisat
     * @covers ::hrpToSat
     * @covers ::initializeTagParsers
     * @covers ::parseTagsFromWords
     * @covers ::routingInfoParser
     * @covers ::tagsContainItem
     * @covers ::tagsItems
     * @covers ::wordsToBuffer
     * @covers ::wordsToHex
     * @covers ::wordsToIntBE
     * @covers ::wordsToUtf8
     * @dataProvider providerOfInvalidScenarios
     */
    public function testInvalidScenarios(string $invoice, string $expectedMessage, string $expectedInstanceOf): void
    {
        $this->expectExceptionMessage($expectedMessage);
        $this->expectException($expectedInstanceOf);

        $this->decoder->decode($invoice);
    }
}
