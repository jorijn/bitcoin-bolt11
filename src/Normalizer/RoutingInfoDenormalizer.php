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

use Jorijn\Bitcoin\Bolt11\Model\RoutingInfo;

class RoutingInfoDenormalizer
{
    use DenormalizerTrait;

    public function denormalize(array $data, $type)
    {
        if ($type === RoutingInfo::class.'[]') {
            return array_map([$this, 'denormalizeRoutingInfo'], $data);
        }

        return $this->denormalizeRoutingInfo($data);
    }

    /** @noinspection PhpIncompatibleReturnTypeInspection */
    protected function denormalizeRoutingInfo(array $routingInfo): RoutingInfo
    {
        return $this->denormalizerDataWithSetters(new RoutingInfo(), $routingInfo);
    }
}
