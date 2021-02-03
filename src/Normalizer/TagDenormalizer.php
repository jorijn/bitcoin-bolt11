<?php

declare(strict_types=1);

namespace Jorijn\Bitcoin\Bolt11\Normalizer;

use Jorijn\Bitcoin\Bolt11\Encoder\PaymentRequestDecoder;
use Jorijn\Bitcoin\Bolt11\Model\RoutingInfo;
use Jorijn\Bitcoin\Bolt11\Model\Tag;
use Jorijn\Bitcoin\Bolt11\Model\TagInterface;
use Jorijn\Bitcoin\Bolt11\Model\UnknownTag;

class TagDenormalizer
{
    use DenormalizerTrait;

    /** @var FallbackAddressDenormalizer */
    protected $fallbackAddressDenormalizer;
    /** @var RoutingInfoDenormalizer */
    protected $routingInfoDenormalizer;

    public function __construct(
        FallbackAddressDenormalizer $fallbackAddressDenormalizer = null,
        RoutingInfoDenormalizer $routingInfoDenormalizer = null
    ) {
        if (null === $fallbackAddressDenormalizer) {
            $fallbackAddressDenormalizer = new FallbackAddressDenormalizer();
        }

        if (null === $routingInfoDenormalizer) {
            $routingInfoDenormalizer = new RoutingInfoDenormalizer();
        }

        $this->fallbackAddressDenormalizer = $fallbackAddressDenormalizer;
        $this->routingInfoDenormalizer = $routingInfoDenormalizer;
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
