<?php

declare(strict_types=1);

use Jorijn\Bitcoin\Bolt11\Encoder\PaymentRequestDecoder;
use Jorijn\Bitcoin\Bolt11\Model\Tag;
use Jorijn\Bitcoin\Bolt11\Normalizer\PaymentRequestDenormalizer;

require dirname(__DIR__).DIRECTORY_SEPARATOR.'vendor'.DIRECTORY_SEPARATOR.'autoload.php';

$invoice = 'lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpuaztrnwngzn3kdzw5hydlzf03qdgm2hdq27cqv3agm2awhz5se903vruatfhq77w3ls4evs3ch9zw97j25emudupq63nyw24cg27h2rspfj9srp';

$decoder = new PaymentRequestDecoder();
$denormalizer = new PaymentRequestDenormalizer();

$paymentRequest = $denormalizer->denormalize($decoder->decode($invoice));

echo 'satoshis: '.var_export($paymentRequest->getSatoshis(), true).PHP_EOL;
echo 'description: '.$paymentRequest->findTagByName(Tag::DESCRIPTION)->getData().PHP_EOL;
echo 'expiry: '.$paymentRequest->findTagByName(Tag::EXPIRE_TIME)->getData().PHP_EOL;
echo 'payment before: '.print_r($paymentRequest->getExpiryDateTime(), true).PHP_EOL;
