<?php

declare(strict_types=1);

namespace Jorijn\Bitcoin\Bolt11\Model;

interface TagInterface
{
    public function getTagName(): string;

    /**
     * @return mixed
     */
    public function getData();
}
