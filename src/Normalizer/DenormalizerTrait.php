<?php

declare(strict_types=1);

namespace Jorijn\Bitcoin\Bolt11\Normalizer;

use Jorijn\Bitcoin\Bolt11\Exception\UnableToDenormalizeException;

trait DenormalizerTrait
{
    public function denormalizerDataWithSetters(object $model, array $data): object
    {
        foreach ($data as $key => $value) {
            if (0 === strpos($key, '_')) { // skip private attributes
                continue;
            }

            $method = 'set'.str_replace('_', '', ucwords($key, '_'));

            if (!method_exists($model, $method)) {
                throw new UnableToDenormalizeException(sprintf('encountered denormalize error: method %s unavailable', $method));
            }

            $model->{$method}($value);
        }

        return $model;
    }
}
