<?php

declare(strict_types=1);

namespace Jorijn\Bitcoin\Bolt11\Model;

class Tag implements TagInterface
{
    /** @var string */
    public const PAYMENT_HASH = 'payment_hash';
    /** @var string */
    public const DESCRIPTION = 'description';
    /** @var string */
    public const PAYEE_NODE_KEY = 'payee_node_key';
    /** @var string */
    public const PURPOSE_COMMIT_HASH = 'purpose_commit_hash';
    /** @var string */
    public const EXPIRE_TIME = 'expire_time';
    /** @var string */
    public const MIN_FINAL_CLTV_EXPIRY = 'min_final_cltv_expiry';
    /** @var string */
    public const FALLBACK_ADDRESS = 'fallback_address';
    /** @var string */
    public const ROUTING_INFO = 'routing_info';
    /** @var string */
    public const SECRET = 'secret';

    /** @var string */
    protected $tagName;
    /** @var mixed */
    protected $data;

    public function getTagName(): string
    {
        return $this->tagName;
    }

    public function setTagName(string $tagName): void
    {
        $this->tagName = $tagName;
    }

    /**
     * @return mixed
     */
    public function getData()
    {
        return $this->data;
    }

    /**
     * @param mixed $data
     */
    public function setData($data): void
    {
        $this->data = $data;
    }
}
