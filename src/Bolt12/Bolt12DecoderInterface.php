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

namespace Jorijn\Bitcoin\Bolt12;

use Jorijn\Bitcoin\Bolt12\Exception\Bolt12DecodeException;
use Jorijn\Bitcoin\Bolt12\Model\Invoice;
use Jorijn\Bitcoin\Bolt12\Model\InvoiceRequest;
use Jorijn\Bitcoin\Bolt12\Model\Offer;

/**
 * Type against this interface to swap the decoder in tests, or to decorate it
 * without extending the final Bolt12Decoder.
 */
interface Bolt12DecoderInterface
{
    /**
     * Decodes any BOLT #12 string, choosing the type by its prefix.
     *
     * @throws Bolt12DecodeException for every string that is not valid
     */
    public function decode(string $string): Invoice|InvoiceRequest|Offer;

    /**
     * Decodes an offer ("lno1...").
     *
     * @throws Bolt12DecodeException for every string that is not a valid offer
     */
    public function decodeOffer(string $offer): Offer;

    /**
     * Decodes an invoice request ("lnr1...") and verifies its signature.
     *
     * @throws Bolt12DecodeException for every string that is not a valid invoice request
     */
    public function decodeInvoiceRequest(string $invoiceRequest): InvoiceRequest;

    /**
     * Decodes an invoice ("lni1...") and verifies its signature.
     *
     * @throws Bolt12DecodeException for every string that is not a valid invoice
     */
    public function decodeInvoice(string $invoice): Invoice;
}
