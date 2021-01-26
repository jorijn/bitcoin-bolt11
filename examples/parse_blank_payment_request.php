<?php

declare(strict_types=1);

use Jorijn\Bitcoin\Bolt11\Encoder\PaymentRequestDecoder;
use Jorijn\Bitcoin\Bolt11\Model\Tag;
use Jorijn\Bitcoin\Bolt11\Normalizer\PaymentRequestDenormalizer;

require dirname(__DIR__).DIRECTORY_SEPARATOR.'vendor'.DIRECTORY_SEPARATOR.'autoload.php';

$invoice = 'lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq8rkx3yf5tcsyz3d73gafnh3cax9rn449d9p5uxz9ezhhypd0elx87sjle52x86fux2ypatgddc6k63n7erqz25le42c4u4ecky03ylcqca784w';

$decoder = new PaymentRequestDecoder();
$denormalizer = new PaymentRequestDenormalizer();

$paymentRequest = $denormalizer->denormalize($decoder->decode($invoice));

echo 'satoshis: '.var_export($paymentRequest->getSatoshis(), true).PHP_EOL;
echo 'to node public key: '.$paymentRequest->getPayeeNodeKey().PHP_EOL;
echo 'with payment hash: '.$paymentRequest->findTagByName(Tag::PAYMENT_HASH)->getData().PHP_EOL;
