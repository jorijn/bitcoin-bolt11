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
