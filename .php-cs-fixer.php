<?php

$header = <<<'EOF'
This file is part of the PHP Bitcoin BOLT11 package.

(c) Jorijn Schrijvershof <jorijn@jorijn.com>

This source file is subject to the MIT license that is bundled
with this source code in the file LICENSE.
EOF;

$finder = PhpCsFixer\Finder::create()
    ->in(__DIR__)
    ->exclude('vendor');

return (new PhpCsFixer\Config())
    ->setRiskyAllowed(true)
    ->setRules(
        [
            '@Symfony' => true,
            '@Symfony:risky' => true,
            '@PhpCsFixer' => true,
            '@PhpCsFixer:risky' => true,
            'array_syntax' => ['syntax' => 'short'],
            'general_phpdoc_annotation_remove' => ['annotations' => ['expectedDeprecation']],
            'header_comment' => ['header' => $header],
            // A typed "@var" right before "return" is how PHPStan learns the shape
            // of decoded JSON; without this the rule turns it into a plain comment.
            'phpdoc_to_comment' => ['allow_before_return_statement' => true],
            'method_argument_space' => [
                'on_multiline' => 'ensure_fully_multiline',
            ],
        ]
    )
    ->setFinder($finder);
