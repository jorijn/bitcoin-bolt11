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

use BitWasp\Bitcoin\Network\NetworkInterface;

class PaymentRequest
{
    /** @var string */
    protected $prefix;

    /** @var NetworkInterface */
    protected $network;

    /** @var null|int */
    protected $satoshis;

    /** @var null|int */
    protected $milliSatoshis;

    /** @var int */
    protected $timestamp;

    /** @var \DateTimeInterface */
    protected $timestampDateTime;

    /** @var string */
    protected $payeeNodeKey;

    /** @var string */
    protected $signature;

    /** @var int */
    protected $recoveryFlag;

    /** @var TagInterface[] */
    protected $tags = [];

    /** @var null|int */
    protected $expiryTimestamp;

    /** @var null|\DateTimeInterface */
    protected $expiryDateTime;

    public function getPrefix(): string
    {
        return $this->prefix;
    }

    public function setPrefix(string $prefix): void
    {
        $this->prefix = $prefix;
    }

    public function getNetwork(): NetworkInterface
    {
        return $this->network;
    }

    public function setNetwork(NetworkInterface $network): void
    {
        $this->network = $network;
    }

    public function getSatoshis(): ?int
    {
        return $this->satoshis;
    }

    public function setSatoshis(?int $satoshis): void
    {
        $this->satoshis = $satoshis;
    }

    public function getMilliSatoshis(): ?int
    {
        return $this->milliSatoshis;
    }

    public function setMilliSatoshis(?int $milliSatoshis): void
    {
        $this->milliSatoshis = $milliSatoshis;
    }

    public function getTimestamp(): int
    {
        return $this->timestamp;
    }

    public function setTimestamp(int $timestamp): void
    {
        $this->timestamp = $timestamp;
    }

    public function getTimestampDateTime(): \DateTimeInterface
    {
        return $this->timestampDateTime;
    }

    public function setTimestampString(string $timestampString): void
    {
        $this->timestampDateTime = new \DateTime($timestampString);
    }

    public function getPayeeNodeKey(): string
    {
        return $this->payeeNodeKey;
    }

    public function setPayeeNodeKey(string $payeeNodeKey): void
    {
        $this->payeeNodeKey = $payeeNodeKey;
    }

    public function getSignature(): string
    {
        return $this->signature;
    }

    public function setSignature(string $signature): void
    {
        $this->signature = $signature;
    }

    public function getRecoveryFlag(): int
    {
        return $this->recoveryFlag;
    }

    public function setRecoveryFlag(int $recoveryFlag): void
    {
        $this->recoveryFlag = $recoveryFlag;
    }

    /**
     * @return TagInterface[]
     */
    public function getTags(): array
    {
        return $this->tags;
    }

    public function setTags(array $tags): void
    {
        $this->tags = $tags;
    }

    public function findTagByName(string $name): ?TagInterface
    {
        foreach ($this->getTags() as $tag) {
            if ($tag->getTagName() === $name) {
                return $tag;
            }
        }

        return null;
    }

    public function getExpiryTimestamp(): ?int
    {
        return $this->expiryTimestamp;
    }

    public function setExpiryTimestamp(?int $expiryTimestamp): void
    {
        $this->expiryTimestamp = $expiryTimestamp;
    }

    public function getExpiryDateTime(): ?\DateTimeInterface
    {
        return $this->expiryDateTime;
    }

    public function setExpiryDateTime(?string $expiryDateTime): void
    {
        $this->expiryDateTime = null !== $expiryDateTime ? new \DateTime($expiryDateTime) : null;
    }
}
