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

// Decodes an invoice and prints the fields most applications need.
// The invoice is test vector 10 from the BOLT #11 specification.

use Jorijn\Bitcoin\Bolt11\Exception\ExceptionInterface;
use Jorijn\Bitcoin\Bolt11\PaymentRequestDecoder;

require dirname(__DIR__).'/vendor/autoload.php';

$invoice = $argv[1] ?? 'lnbc9678785340p1pwmna7lpp5gc3xfm08u9qy06djf8dfflhugl6p7lgza6dsjxq454gxhj9t7a0sd8dgfkx7cmtwd68yetpd5s9xar0wfjn5gpc8qhrsdfq24f5ggrxdaezqsnvda3kkum5wfjkzmfqf3jkgem9wgsyuctwdus9xgrcyqcjcgpzgfskx6eqf9hzqnteypzxz7fzypfhg6trddjhygrcyqezcgpzfysywmm5ypxxjemgw3hxjmn8yptk7untd9hxwg3q2d6xjcmtv4ezq7pqxgsxzmnyyqcjqmt0wfjjq6t5v4khxsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsxqyjw5qcqp2rzjq0gxwkzc8w6323m55m4jyxcjwmy7stt9hwkwe2qxmy8zpsgg7jcuwz87fcqqeuqqqyqqqqlgqqqqn3qq9q9qrsgqrvgkpnmps664wgkp43l22qsgdw4ve24aca4nymnxddlnp8vh9v2sdxlu5ywdxefsfvm0fq3sesf08uf6q9a2ke0hc9j6z6wlxg5z5kqpu2v9wz';

try {
    $paymentRequest = (new PaymentRequestDecoder())->decode($invoice);
} catch (ExceptionInterface $exception) {
    fwrite(STDERR, 'Not a valid invoice: '.$exception->getMessage().PHP_EOL);

    exit(1);
}

echo 'network:          '.$paymentRequest->getNetwork()->name.PHP_EOL;
echo 'amount (msat):    '.($paymentRequest->getMilliSatoshis() ?? 'any').PHP_EOL;
// The description comes from whoever made the invoice: escape it before
// putting it in HTML. json_encode() does that for a terminal here.
echo 'description:      '.json_encode($paymentRequest->getDescription(), JSON_UNESCAPED_UNICODE).PHP_EOL;
echo 'payee:            '.$paymentRequest->getPayeeNodeKey().PHP_EOL;
echo 'payment hash:     '.$paymentRequest->getPaymentHash().PHP_EOL;
echo 'created:          '.$paymentRequest->getTimestamp()->format(DATE_ATOM).PHP_EOL;
echo 'expires:          '.$paymentRequest->getExpiresAt()->format(DATE_ATOM).PHP_EOL;
echo 'expired:          '.($paymentRequest->isExpired() ? 'yes' : 'no').PHP_EOL;
echo 'feature bits:     '.implode(', ', $paymentRequest->getFeatures()->getBits()).PHP_EOL;

foreach ($paymentRequest->getRouteHints() as $index => $routeHint) {
    echo sprintf('route hint %d:', $index).PHP_EOL;
    foreach ($routeHint->getHops() as $hop) {
        echo sprintf(
            '  via %s over channel %s (fee %d msat + %d ppm, cltv delta %d)',
            $hop->getPublicKey(),
            $hop->getShortChannelIdNotation(),
            $hop->getFeeBaseMsat(),
            $hop->getFeeProportionalMillionths(),
            $hop->getCltvExpiryDelta(),
        ).PHP_EOL;
    }
}
