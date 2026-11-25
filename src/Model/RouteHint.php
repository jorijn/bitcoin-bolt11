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

/**
 * A private route to the payee (one `r` field): the channels to take, in
 * order, from a public node to the destination.
 */
final readonly class RouteHint
{
    /**
     * @param non-empty-list<RouteHintHop> $hops
     */
    public function __construct(private array $hops) {}

    /**
     * @return non-empty-list<RouteHintHop>
     */
    public function getHops(): array
    {
        return $this->hops;
    }

    /**
     * @return list<array{public_key: string, short_channel_id: string, fee_base_msat: int, fee_proportional_millionths: int, cltv_expiry_delta: int}>
     */
    public function toArray(): array
    {
        return array_map(static fn (RouteHintHop $hop): array => $hop->toArray(), $this->hops);
    }
}
