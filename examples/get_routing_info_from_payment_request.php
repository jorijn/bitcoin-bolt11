<?php

declare(strict_types=1);

use Jorijn\Bitcoin\Bolt11\Encoder\PaymentRequestDecoder;
use Jorijn\Bitcoin\Bolt11\Model\RoutingInfo;
use Jorijn\Bitcoin\Bolt11\Model\Tag;
use Jorijn\Bitcoin\Bolt11\Normalizer\PaymentRequestDenormalizer;

require dirname(__DIR__).DIRECTORY_SEPARATOR.'vendor'.DIRECTORY_SEPARATOR.'autoload.php';

$invoice = 'lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzqj9n4evl6mr5aj9f58zp6fyjzup6ywn3x6sk8akg5v4tgn2q8g4fhx05wf6juaxu9760yp46454gpg5mtzgerlzezqcqvjnhjh8z3g2qqdhhwkj';

$decoder = new PaymentRequestDecoder();
$denormalizer = new PaymentRequestDenormalizer();

$paymentRequest = $denormalizer->denormalize($decoder->decode($invoice));

echo 'satoshis: '.var_export($paymentRequest->getSatoshis(), true).PHP_EOL;
echo 'routing info: '.PHP_EOL.PHP_EOL;

/** @var RoutingInfo $routingInfo */
foreach ($paymentRequest->findTagByName(Tag::ROUTING_INFO)->getData() as $index => $routingInfo) {
    echo sprintf('[hop %d] public key: %s', $index, $routingInfo->getPubKey()).PHP_EOL;
    echo sprintf('[hop %d] short channel id: %s', $index, $routingInfo->getShortChannelId()).PHP_EOL;
    echo sprintf('[hop %d] fee base msat: %d', $index, $routingInfo->getFeeBaseMsat()).PHP_EOL;
    echo sprintf(
        '[hop %d] fee proportional millionths: %d',
        $index,
        $routingInfo->getFeeProportionalMillionths()
    ).PHP_EOL;
    echo sprintf('[hop %d] cltv expiry delta: %d', $index, $routingInfo->getCltvExpiryDelta()).PHP_EOL;
    echo PHP_EOL;
}
