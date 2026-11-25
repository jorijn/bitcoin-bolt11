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

// Invoices from before the payment secret (s) became mandatory fail in the
// default strict mode. Lenient mode reads them, for display or archiving.
// Decode in strict mode before paying.

use Jorijn\Bitcoin\Bolt11\Exception\ExceptionInterface;
use Jorijn\Bitcoin\Bolt11\PaymentRequestDecoder;

require dirname(__DIR__).'/vendor/autoload.php';

// A 2019 invoice without a payment secret.
$invoice = 'lnbc9678785340p1pwmna7lpp5gc3xfm08u9qy06djf8dfflhugl6p7lgza6dsjxq454gxhj9t7a0sd8dgfkx7cmtwd68yetpd5s9xar0wfjn5gpc8qhrsdfq24f5ggrxdaezqsnvda3kkum5wfjkzmfqf3jkgem9wgsyuctwdus9xgrcyqcjcgpzgfskx6eqf9hzqnteypzxz7fzypfhg6trddjhygrcyqezcgpzfysywmm5ypxxjemgw3hxjmn8yptk7untd9hxwg3q2d6xjcmtv4ezq7pqxgsxzmnyyqcjqmt0wfjjq6t5v4khxxqyjw5qcqp2rzjq0gxwkzc8w6323m55m4jyxcjwmy7stt9hwkwe2qxmy8zpsgg7jcuwz87fcqqeuqqqyqqqqlgqqqqn3qq9qn07ytgrxxzad9hc4xt3mawjjt8znfv8xzscs7007v9gh9j569lencxa8xeujzkxs0uamak9aln6ez02uunw6rd2ht2sqe4hz8thcdagpleym0j';

try {
    (new PaymentRequestDecoder())->decode($invoice);
} catch (ExceptionInterface $exception) {
    echo 'strict:  '.$exception->getMessage().PHP_EOL;
}

$paymentRequest = (new PaymentRequestDecoder(lenient: true))->decode($invoice);
echo 'lenient: '.$paymentRequest->getMilliSatoshis().' msat, payment secret '.var_export($paymentRequest->getPaymentSecret(), true).PHP_EOL;
