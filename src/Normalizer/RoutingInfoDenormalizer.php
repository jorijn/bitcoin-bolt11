<?php

declare(strict_types=1);

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
