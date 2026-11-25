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
 * One hop of a blinded path: a blinded node id and the data only that node
 * can decrypt.
 */
final readonly class BlindedHop
{
    /**
     * @param string $blindedNodeId          hex, 33-byte compressed public key
     * @param string $encryptedRecipientData hex
     */
    public function __construct(
        private string $blindedNodeId,
        private string $encryptedRecipientData,
    ) {}

    public function getBlindedNodeId(): string
    {
        return $this->blindedNodeId;
    }

    public function getEncryptedRecipientData(): string
    {
        return $this->encryptedRecipientData;
    }

    /**
     * @return array{blinded_node_id: string, encrypted_recipient_data: string}
     */
    public function toArray(): array
    {
        return [
            'blinded_node_id' => $this->blindedNodeId,
            'encrypted_recipient_data' => $this->encryptedRecipientData,
        ];
    }
}
