<?php

declare(strict_types=1);

namespace Jorijn\Bitcoin\Bolt11\Model;

class RoutingInfo
{
    /** @var string */
    protected $pubkey;
    /** @var string */
    protected $shortChannelId;
    /** @var int */
    protected $feeBaseMsat;
    /** @var int */
    protected $feeProportionalMillionths;
    /** @var int */
    protected $cltvExpiryDelta;

    public function getPubKey(): string
    {
        return $this->pubkey;
    }

    public function setPubKey(string $pubkey): void
    {
        $this->pubkey = $pubkey;
    }

    public function getShortChannelId(): string
    {
        return $this->shortChannelId;
    }

    public function setShortChannelId(string $shortChannelId): void
    {
        $this->shortChannelId = $shortChannelId;
    }

    public function getFeeBaseMsat(): int
    {
        return $this->feeBaseMsat;
    }

    public function setFeeBaseMsat(int $feeBaseMsat): void
    {
        $this->feeBaseMsat = $feeBaseMsat;
    }

    public function getFeeProportionalMillionths(): int
    {
        return $this->feeProportionalMillionths;
    }

    public function setFeeProportionalMillionths(int $feeProportionalMillionths): void
    {
        $this->feeProportionalMillionths = $feeProportionalMillionths;
    }

    public function getCltvExpiryDelta(): int
    {
        return $this->cltvExpiryDelta;
    }

    public function setCltvExpiryDelta(int $cltvExpiryDelta): void
    {
        $this->cltvExpiryDelta = $cltvExpiryDelta;
    }
}
