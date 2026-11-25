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

// Verifies a BOLT #12 payer proof and prints what it shows. The default is
// the "with_note" proof from the BOLT #12 payer proof test vectors.
//
// Usage: php verify_payer_proof.php [lnp1...] [expected node id] [expected note]

use Jorijn\Bitcoin\Bolt11\Exception\ExceptionInterface;
use Jorijn\Bitcoin\Bolt12\PayerProofDecoder;

require dirname(__DIR__).'/vendor/autoload.php';

$string = $argv[1] ?? 'lnp1tqssxfr986kyx3ygqqkvq6alklcslcvfj834l8lyxqkmafkjx57up2cu4qs89ntwss3vgplmd5ycdy83zv9hmmt7ctmltcwnp0va2g0sz5mr0yasyypyhs4rzfj320c8uu8qh2cgwf8xhp0zzluv6c5vad3fwsj8hdyn8qhsgq9rxgj9dzm24ehdy5sp90tluyrjcqltmjnl538etvplrngfhc5tp2punsepqktcekqd5p5f09nzeq86qrlj2rxdcngckuyll5w84cce79qz53lesac2aq2pr8tg9fa3na7wnczs5wa5nkds5qcugmvuk4arqawacga8gtmdxw7yaj8pw7pjwj2tafmd9mjkgcj7nxlmjhxzpxnhyt7s86fqqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyql6ql2qcqsyk26tw5l6qlt5zlcev436mafhnw2k5qmt8uzcew9q6mlgdg5wdlhr9l3lnl2awk5rw2qdaxw2f4x5r2wpvax8mvf4qewx89ejwwluxnmthtjxtfjcq4tekwyfdfmx9cqe8ksuveseep97lccltp0c82kdg6ydppeya8suvtflxps7tpswr8m45flmccwudkdw9p4jytya5fqgz5u6k2uj6zq4jve32ml48r587uahkcd34r0hcadxv6qp0g87v5dekmqppushjwjm07s8mrq7t027heshc7wmz0u0sjdgg5pn0cx4u8y3gc5ywaapcnrfu7rmenlqxgux5qqy364fwxs5xtgnznef0eaazvcy4c30rvnrtlmv48scxn7j2mhh83cgdjs7mxha62tvaf7480n2vm3pvzdae5x45mk29d9e07s8mgfw3jhxapqdehhgeg';
$expectedNodeId = $argv[2] ?? null;
$expectedNote = $argv[3] ?? null;

try {
    $proof = (new PayerProofDecoder())->decode($string);
} catch (ExceptionInterface $exception) {
    fwrite(STDERR, 'Not a valid payer proof: '.$exception->getMessage().PHP_EOL);

    exit(1);
}

echo 'paid by:          '.$proof->getPayerId().PHP_EOL;
echo 'signed by:        '.$proof->getNodeId().PHP_EOL;
echo 'payment hash:     '.$proof->getPaymentHash().PHP_EOL;
echo 'amount (msat):    '.($proof->getAmount() ?? 'not shown').PHP_EOL;
// Text in a proof comes from the payer and the offer's issuer: escape it
// before putting it in HTML. json_encode() does that for a terminal here.
echo 'description:      '.json_encode($proof->getDescription(), JSON_UNESCAPED_UNICODE).PHP_EOL;
echo 'note:             '.json_encode($proof->getNote(), JSON_UNESCAPED_UNICODE).PHP_EOL;
echo 'fields shown:     '.implode(', ', array_keys($proof->getDisclosedFields())).PHP_EOL;
echo 'fields hidden:    '.$proof->getOmittedFieldCount().PHP_EOL;

// The decoder checks the proof is genuine; whether it is about your node and
// was made for you is for you to check.
if (null !== $expectedNodeId && $proof->getNodeId() !== strtolower($expectedNodeId)) {
    fwrite(STDERR, 'The invoice was not signed by the node you expected.'.PHP_EOL);

    exit(1);
}

if (null !== $expectedNote && $proof->getNote() !== $expectedNote) {
    fwrite(STDERR, 'The proof does not carry the note you asked for.'.PHP_EOL);

    exit(1);
}
