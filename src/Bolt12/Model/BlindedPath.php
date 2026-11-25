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

namespace Jorijn\Bitcoin\Bolt12\Model;

/**
 * A blinded path (BOLT #4): a route to the recipient that hides who the
 * recipient is. Only the introduction node is visible; the hops after it are
 * blinded.
 *
 * @see https://github.com/lightning/bolts/blob/master/04-onion-routing.md#route-blinding
 *
 * @phpstan-type BlindedPathArray array{introduction_node: string, first_path_key: string, hops: list<array{blinded_node_id: string, encrypted_recipient_data: string}>}
 */
final readonly class BlindedPath
{
    /**
     * @param string           $introductionNode hex: a 33-byte public key, or 9 bytes (direction and short channel id)
     * @param string           $firstPathKey     hex, 33-byte compressed public key
     * @param list<BlindedHop> $hops             at least one
     */
    public function __construct(
        private string $introductionNode,
        private string $firstPathKey,
        private array $hops,
    ) {}

    /**
     * The first node of the path (`first_node_id`) as written: either a
     * public key or a reference to one end of a channel. Use
     * getIntroductionNodeId() or getIntroductionShortChannelId() to tell them apart.
     */
    public function getIntroductionNode(): string
    {
        return $this->introductionNode;
    }

    /**
     * The introduction node's public key, or null when the path names it by
     * a channel instead.
     */
    public function getIntroductionNodeId(): ?string
    {
        return 66 === \strlen($this->introductionNode) ? $this->introductionNode : null;
    }

    /**
     * The channel that names the introduction node, as "block x transaction
     * x output", or null when the path gives a public key.
     */
    public function getIntroductionShortChannelId(): ?string
    {
        if (18 !== \strlen($this->introductionNode)) {
            return null;
        }

        // short_channel_id: 3 bytes block height, 3 bytes transaction index,
        // 2 bytes output index (BOLT #7), after the direction byte.
        return \sprintf(
            '%dx%dx%d',
            hexdec(substr($this->introductionNode, 2, 6)),
            hexdec(substr($this->introductionNode, 8, 6)),
            hexdec(substr($this->introductionNode, 14, 4)),
        );
    }

    /**
     * With a channel reference: 0 for the channel's node_id_1, 1 for
     * node_id_2 (BOLT #7). Null when the path gives a public key.
     */
    public function getIntroductionDirection(): ?int
    {
        return 18 === \strlen($this->introductionNode) ? (int) hexdec(substr($this->introductionNode, 0, 2)) : null;
    }

    public function getFirstPathKey(): string
    {
        return $this->firstPathKey;
    }

    /**
     * @return list<BlindedHop>
     */
    public function getHops(): array
    {
        return $this->hops;
    }

    /**
     * The blinded node id of the last hop: the recipient, under this path's
     * blinding. An invoice for an offer without offer_issuer_id is signed
     * with this key.
     */
    public function getFinalBlindedNodeId(): string
    {
        return $this->hops[\count($this->hops) - 1]->getBlindedNodeId();
    }

    /**
     * @return BlindedPathArray
     */
    public function toArray(): array
    {
        return [
            'introduction_node' => $this->introductionNode,
            'first_path_key' => $this->firstPathKey,
            'hops' => array_map(static fn (BlindedHop $hop): array => $hop->toArray(), $this->hops),
        ];
    }
}
