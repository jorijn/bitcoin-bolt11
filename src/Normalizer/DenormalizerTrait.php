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
