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

// An invoice can commit to a long description with its SHA-256 hash (h)
// instead of carrying it (d). The payer gets the description some other way
// and checks it against the hash. Test vector 3 from the BOLT #11 specification.

use Jorijn\Bitcoin\Bolt11\PaymentRequestDecoder;

require dirname(__DIR__).'/vendor/autoload.php';

$invoice = 'lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qrsgq7ea976txfraylvgzuxs8kgcw23ezlrszfnh8r6qtfpr6cxga50aj6txm9rxrydzd06dfeawfk6swupvz4erwnyutnjq7x39ymw6j38gp7ynn44';
$description = 'One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon';

$paymentRequest = (new PaymentRequestDecoder())->decode($invoice);

echo 'description hash: '.$paymentRequest->getDescriptionHash().PHP_EOL;
echo 'matches:          '.($paymentRequest->verifyDescriptionHash($description) ? 'yes' : 'no').PHP_EOL;
echo 'other text:       '.($paymentRequest->verifyDescriptionHash('something else') ? 'yes' : 'no').PHP_EOL;
