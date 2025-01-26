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

use Jorijn\Bitcoin\Bolt11\Encoder\PaymentRequestDecoder;
use Jorijn\Bitcoin\Bolt11\Model\RoutingInfo;
use Jorijn\Bitcoin\Bolt11\Model\Tag;
use Jorijn\Bitcoin\Bolt11\Model\TagInterface;
use Jorijn\Bitcoin\Bolt11\Model\UnknownTag;

class TagDenormalizer
{
    use DenormalizerTrait;

    private FallbackAddressDenormalizer $fallbackAddressDenormalizer;

    private RoutingInfoDenormalizer $routingInfoDenormalizer;

    public function __construct(
        ?FallbackAddressDenormalizer $fallbackAddressDenormalizer = null,
        ?RoutingInfoDenormalizer $routingInfoDenormalizer = null
    ) {
        $this->fallbackAddressDenormalizer = $fallbackAddressDenormalizer ?? new FallbackAddressDenormalizer();
        $this->routingInfoDenormalizer = $routingInfoDenormalizer ?? new RoutingInfoDenormalizer();
    }

    public function denormalize(array $data, $type)
    {
        if ($type === Tag::class.'[]') {
            return array_map([$this, 'denormalizeTag'], $data);
        }

        return $this->denormalizeTag($data);
    }

    /** @noinspection PhpIncompatibleReturnTypeInspection */
    protected function denormalizeTag(array $tag): TagInterface
    {
        if (PaymentRequestDecoder::NAME_UNKNOWN_TAG === $tag['tag_name'] ?? null) {
            return $this->denormalizerDataWithSetters(new UnknownTag(), $tag['data']);
        }

        if (Tag::ROUTING_INFO === $tag['tag_name']) {
            $tag['data'] = $this->routingInfoDenormalizer->denormalize($tag['data'], RoutingInfo::class.'[]');
        }

        if (Tag::FALLBACK_ADDRESS === $tag['tag_name']) {
            $tag['data'] = $this->fallbackAddressDenormalizer->denormalize($tag['data']);
        }

        return $this->denormalizerDataWithSetters(new Tag(), $tag);
    }
}
