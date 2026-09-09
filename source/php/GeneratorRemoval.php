<?php

namespace WPMUSecurity;

use WpService\WpService;

class GeneratorRemoval
{
    public function __construct(private WpService $wpService)
    {
    }

    /**
     * Register hooks for removing generator metadata.
     *
     * @return void
     */
    public function addHooks(): void
    {
        $this->wpService->addFilter('the_generator', [$this, 'removeGenerator'], 10, 0);
    }

    /**
     * Remove generator metadata from WordPress output.
     *
     * @return string An empty generator value.
     */
    public function removeGenerator(): string
    {
        return '';
    }
}