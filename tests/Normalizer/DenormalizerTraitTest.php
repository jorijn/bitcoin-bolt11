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

namespace Tests\Jorijn\Bitcoin\Bolt11\Normalizer;

use Jorijn\Bitcoin\Bolt11\Exception\UnableToDenormalizeException;
use Jorijn\Bitcoin\Bolt11\Normalizer\DenormalizerTrait;
use PHPUnit\Framework\TestCase;

/**
 * @coversDefaultClass \Jorijn\Bitcoin\Bolt11\Normalizer\DenormalizerTrait
 *
 * @internal
 */
final class DenormalizerTraitTest extends TestCase
{
    /**
     * @covers ::denormalizerDataWithSetters
     */
    public function testDenormalizerTraitErrorHandler(): void
    {
        $mock = $this->getMockForTrait(DenormalizerTrait::class);

        $this->expectException(UnableToDenormalizeException::class);
        $this->expectExceptionMessage('encountered denormalize error: method setNonExistent unavailable');

        $mock->denormalizerDataWithSetters($this->createMock(\stdClass::class), ['non_existent' => 'value']);
    }

    /**
     * @covers ::denormalizerDataWithSetters
     * @noinspection MockingMethodsCorrectnessInspection
     */
    public function testDenormalizerTraitAttributeFiller(): void
    {
        $mock = $this->getMockForTrait(DenormalizerTrait::class);

        $model = $this
            ->getMockBuilder(\stdClass::class)
            ->addMethods(['setValueOne', 'setValueTwo'])
            ->getMock()
        ;

        $model->expects(static::once())->method('setValueOne')->with($value1 = random_int(1000, 2000));
        $model->expects(static::once())->method('setValueTwo')->with($value2 = random_int(1000, 2000));

        $mock->denormalizerDataWithSetters(
            $model,
            ['value_one' => $value1, 'value_two' => $value2, '_private_value' => random_int(1000, 2000)]
        );
    }
}
