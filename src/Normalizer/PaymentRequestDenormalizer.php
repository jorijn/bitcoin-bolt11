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

use Jorijn\Bitcoin\Bolt11\Model\PaymentRequest;
use Jorijn\Bitcoin\Bolt11\Model\Tag;

final class PaymentRequestDenormalizer
{
    use DenormalizerTrait;

    private TagDenormalizer $tagDenormalizer;

    public function __construct(?TagDenormalizer $tagDenormalizer = null)
    {
        $this->tagDenormalizer = $tagDenormalizer ?? new TagDenormalizer();
    }

    /** @noinspection PhpIncompatibleReturnTypeInspection */
    public function denormalize(array $data): PaymentRequest
    {
        if (isset($data['tags'])) {
            $data['tags'] = $this->tagDenormalizer->denormalize($data['tags'], Tag::class.'[]');
        }

        return $this->denormalizerDataWithSetters(new PaymentRequest(), $data);
    }
}
