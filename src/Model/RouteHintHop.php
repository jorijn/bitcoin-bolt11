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

namespace Jorijn\Bitcoin\Bolt11\Model;

/**
 * One channel of a private route (an entry in an `r` field).
 *
 * The fields match the channel_update message of BOLT #7: the node at the
 * start of the channel, the channel, and what that node charges to forward.
 */
final readonly class RouteHintHop
{
    /**
     * @param string $publicKey      hex, 33 bytes: the node at the start of the channel
     * @param string $shortChannelId hex, 8 bytes
     */
    public function __construct(
        private string $publicKey,
        private string $shortChannelId,
        private int $feeBaseMsat,
        private int $feeProportionalMillionths,
        private int $cltvExpiryDelta,
    ) {}

    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    /**
     * The short channel id as 16 hex characters.
     */
    public function getShortChannelId(): string
    {
        return $this->shortChannelId;
    }

    /**
     * The short channel id as block x transaction x output ("700000x1234x1"),
     * the form Lightning nodes and explorers show.
     */
    public function getShortChannelIdNotation(): string
    {
        $block = (int) hexdec(substr($this->shortChannelId, 0, 6));
        $transaction = (int) hexdec(substr($this->shortChannelId, 6, 6));
        $output = (int) hexdec(substr($this->shortChannelId, 12, 4));

        return $block.'x'.$transaction.'x'.$output;
    }

    public function getFeeBaseMsat(): int
    {
        return $this->feeBaseMsat;
    }

    public function getFeeProportionalMillionths(): int
    {
        return $this->feeProportionalMillionths;
    }

    public function getCltvExpiryDelta(): int
    {
        return $this->cltvExpiryDelta;
    }

    /**
     * @return array{public_key: string, short_channel_id: string, fee_base_msat: int, fee_proportional_millionths: int, cltv_expiry_delta: int}
     */
    public function toArray(): array
    {
        return [
            'public_key' => $this->publicKey,
            'short_channel_id' => $this->shortChannelId,
            'fee_base_msat' => $this->feeBaseMsat,
            'fee_proportional_millionths' => $this->feeProportionalMillionths,
            'cltv_expiry_delta' => $this->cltvExpiryDelta,
        ];
    }
}
