<?php

namespace WPMUSecurity;

use PHPUnit\Framework\TestCase;
use WpService\Implementations\FakeWpService;

class GeneratorRemovalTest extends TestCase
{
    /**
     * @testdox addHooks() registers the generator filter
     */
    public function testAddHooksRegistersGeneratorFilter(): void
    {
        $wpService = new FakeWpService([
            'addFilter' => true,
        ]);
        $generatorRemoval = new GeneratorRemoval($wpService);

        $generatorRemoval->addHooks();

        static::assertSame(
            ['the_generator', [$generatorRemoval, 'removeGenerator'], 10, 0],
            $wpService->methodCalls['addFilter'][0]
        );
    }

    /**
     * @testdox removeGenerator() returns an empty value
     */
    public function testRemoveGeneratorReturnsEmptyValue(): void
    {
        $generatorRemoval = new GeneratorRemoval(new FakeWpService());

        $result = $generatorRemoval->removeGenerator();

        static::assertSame('', $result);
    }
}