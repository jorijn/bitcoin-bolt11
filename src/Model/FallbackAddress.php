<?php

declare(strict_types=1);

namespace Jorijn\Bitcoin\Bolt11\Model;

class FallbackAddress
{
    /** @var int */
    protected $code;
    /** @var string */
    protected $address;
    /** @var string */
    protected $addressHash;

    public function getCode(): int
    {
        return $this->code;
    }

    public function setCode(int $code): void
    {
        $this->code = $code;
    }

    public function getAddress(): string
    {
        return $this->address;
    }

    public function setAddress(string $address): void
    {
        $this->address = $address;
    }

    public function getAddressHash(): string
    {
        return $this->addressHash;
    }

    public function setAddressHash(string $addressHash): void
    {
        $this->addressHash = $addressHash;
    }
}
