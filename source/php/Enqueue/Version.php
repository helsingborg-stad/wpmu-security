<?php

namespace WPMUSecurity\Enqueue;

use WpService\WpService;
use WPMUSecurity\Config;

class Version
{
    public function __construct(private WpService $wpService, private Config $config)
    {
    }

    /**
     * Register asset URL filters.
     *
     * @return void
     */
    public function addHooks(): void
    {
        $this->wpService->addFilter('script_loader_src', [$this, 'obfuscateVersion']);
        $this->wpService->addFilter('style_loader_src', [$this, 'obfuscateVersion']);
    }

    /**
     * Replace the WordPress version query value in an asset URL.
     *
     * @param string $source Asset URL.
     * @return string The asset URL with its core version obfuscated when applicable.
     */
    public function obfuscateVersion(string $source): string
    {
        $wordpressVersion = $this->wpService->getBloginfo('version');
        if ($wordpressVersion === '') {
            return $source;
        }

        $salt = $this->config->getAssetVersionObfuscationSalt();
        if ($salt === '') {
            return $source;
        }

        $version = rawurlencode($wordpressVersion);
        $hash = hash_hmac('sha256', $wordpressVersion, $salt);

        return preg_replace(
            '/([?&]ver=)' . preg_quote($version, '/') . '(?=(&|$))/',
            '${1}' . $hash,
            $source
        ) ?? $source;
    }
}