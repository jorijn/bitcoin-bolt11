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

// Lists the on-chain fallback addresses of an invoice. Test vectors 5
// (P2PKH, with route hints) and 9 (taproot) from the BOLT #11 specification.

use Jorijn\Bitcoin\Bolt11\Model\FallbackAddress;
use Jorijn\Bitcoin\Bolt11\PaymentRequestDecoder;

require dirname(__DIR__).'/vendor/autoload.php';

$decoder = new PaymentRequestDecoder();

foreach ([
    'lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzq9qrsgqdfjcdk6w3ak5pca9hwfwfh63zrrz06wwfya0ydlzpgzxkn5xagsqz7x9j4jwe7yj7vaf2k9lqsdk45kts2fd0fkr28am0u4w95tt2nsq76cqw0',
    'lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfp4pptdvg0d2nj99568qn6ssdy4cygnwuxgw2ukmnwgwz7jpqjz2kszs9qrsgqy606dznq28exnydt2r4c29y56xjtn3sk4mhgjtl4pg2y4ar3249rq4ajlmj9jy8zvlzw7cr8mggqzm842xfr0v72rswzq9xvr4hknfsqwmn6xd',
] as $invoice) {
    foreach ($decoder->decode($invoice)->getFallbackAddresses() as $address) {
        $type = match ($address->getVersion()) {
            FallbackAddress::VERSION_P2PKH => 'P2PKH',
            FallbackAddress::VERSION_P2SH => 'P2SH',
            0 => 'segwit v0',
            1 => 'taproot',
            default => 'segwit v'.$address->getVersion(),
        };

        echo $type.': '.$address->getAddress().PHP_EOL;
    }
}
