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

namespace Jorijn\Bitcoin\Bolt11\Normalizer;

use Jorijn\Bitcoin\Bolt11\Model\FallbackAddress;

class FallbackAddressDenormalizer
{
    use DenormalizerTrait;

    /** @noinspection PhpIncompatibleReturnTypeInspection */
    public function denormalize(array $data): FallbackAddress
    {
        return $this->denormalizerDataWithSetters(new FallbackAddress(), $data);
    }
}
