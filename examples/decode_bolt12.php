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

// Decodes a BOLT #12 offer, invoice request or invoice and prints what a
// wallet would show. The default is the "with currency" offer from the
// BOLT #12 test vectors.

use Jorijn\Bitcoin\Bolt11\Exception\ExceptionInterface;
use Jorijn\Bitcoin\Bolt12\Bolt12Decoder;
use Jorijn\Bitcoin\Bolt12\Model\Chain;
use Jorijn\Bitcoin\Bolt12\Model\Invoice;
use Jorijn\Bitcoin\Bolt12\Model\InvoiceRequest;
use Jorijn\Bitcoin\Bolt12\Model\Offer;

require dirname(__DIR__).'/vendor/autoload.php';

$string = $argv[1] ?? 'lno1qcp4256ypqpzwyq2p32x2um5ypmx2cm5dae8x93pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpj';

try {
    $decoded = (new Bolt12Decoder())->decode($string);
} catch (ExceptionInterface $exception) {
    fwrite(STDERR, 'Not a valid BOLT #12 string: '.$exception->getMessage().PHP_EOL);

    exit(1);
}

$offer = match (true) {
    $decoded instanceof Offer => $decoded,
    $decoded instanceof InvoiceRequest, $decoded instanceof Invoice => $decoded->getOffer(),
};

echo 'type:             '.(new ReflectionClass($decoded))->getShortName().PHP_EOL;
echo 'chains:           '.implode(', ', array_map(
    static fn (string $chain): string => Chain::toNetwork($chain)->name ?? $chain,
    $offer->getChains(),
)).PHP_EOL;

// An amount in another currency is in its smallest unit (cents for USD).
$amount = $offer->getAmount();
echo 'price:            '.(null === $amount ? 'any' : $amount.' '.($offer->getCurrency() ?? 'msat')).PHP_EOL;

// The description and issuer come from whoever made the offer: escape them
// before putting them in HTML. json_encode() does that for a terminal here.
echo 'description:      '.json_encode($offer->getDescription(), JSON_UNESCAPED_UNICODE).PHP_EOL;
echo 'issuer:           '.json_encode($offer->getIssuer(), JSON_UNESCAPED_UNICODE).PHP_EOL;
echo 'issuer id:        '.($offer->getIssuerId() ?? 'none, reachable through blinded paths only').PHP_EOL;
echo 'blinded paths:    '.count($offer->getPaths()).PHP_EOL;
echo 'expires:          '.($offer->getAbsoluteExpiry()?->format(DATE_ATOM) ?? 'never').PHP_EOL;

if ($decoded instanceof Invoice) {
    echo 'amount (msat):    '.$decoded->getAmount().PHP_EOL;
    echo 'payment hash:     '.$decoded->getPaymentHash().PHP_EOL;
    echo 'signed by:        '.$decoded->getNodeId().PHP_EOL;
    echo 'invoice expires:  '.$decoded->getExpiresAt()->format(DATE_ATOM).PHP_EOL;
}
