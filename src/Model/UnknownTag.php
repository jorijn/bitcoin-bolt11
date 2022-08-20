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

class UnknownTag implements TagInterface
{
    /** @var int */
    protected $tagCode;

    /** @var string */
    protected $words;

    public function getTagCode(): int
    {
        return $this->tagCode;
    }

    public function setTagCode(int $tagCode): void
    {
        $this->tagCode = $tagCode;
    }

    public function getWords(): string
    {
        return $this->words;
    }

    public function setWords(string $words): void
    {
        $this->words = $words;
    }

    public function getTagName(): string
    {
        return (string) $this->getTagCode();
    }

    public function getData(): string
    {
        return $this->getWords();
    }
}
