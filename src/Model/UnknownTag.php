<?php

declare(strict_types=1);

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
