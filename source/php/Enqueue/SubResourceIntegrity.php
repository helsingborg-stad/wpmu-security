<?php

namespace WPMUSecurity\Enqueue;

use WpService\WpService;
use WPMUSecurity\Config;

class SubResourceIntegrity
{
    public function __construct(private WpService $wpService, private Config $config){}

    /**
     * Adds hooks for the password reset functionality.
     *
     * @return void
     */
    public function addHooks()
    {
      $this->wpService->addFilter('script_loader_tag', [$this, 'addSriToScript'], 10, 3);
      $this->wpService->addFilter('style_loader_tag', [$this, 'addSriToStyle'], 10, 4);
    }

    /**
     * Adds Subresource Integrity (SRI) attributes to script tags.
     *
     * @param string $tag The HTML tag for the script or style.
     * @param string $handle The handle of the script or style.
     * @param string $src The source URL of the script or style.
     * @return string The modified HTML tag with SRI attributes.
     */
    public function addSriToScript(string $tag, string $handle, string $src): string
    {
        $integrity = $this->maybeGetCachedIntegrityHash($src);
        if ($integrity) {
            $tag = str_replace(' src=', ' integrity="' . esc_attr($integrity) . '" crossorigin="anonymous" src=', $tag);
        }
        return $tag;
    }

    /**
     * Adds Subresource Integrity (SRI) attributes to style tags.
     *
     * @param string $tag The HTML tag for the style.
     * @param string $handle The handle of the style.
     * @param string $href The href URL of the style.
     * @param string|null $media Optional media attribute for the style.
     * @return string The modified HTML tag with SRI attributes.
     */
    public function addSriToStyle(string $tag, string $handle, string $href, ?string $media = null): string
    {
        $integrity = $this->maybeGetCachedIntegrityHash($href);

        if ($integrity) {
          $tag = str_replace(' href=', ' integrity="' . esc_attr($integrity) . '" crossorigin="anonymous" href=', $tag);
        }
        return $tag;
    }

    /**
     * Attempts to get a cached Subresource Integrity (SRI) hash for a given source URL.
     * If the hash is not cached, it generates a new one and caches it.
     *
     * @param string $src The source URL of the script or style.
     * @return string|null The cached SRI hash if available, null otherwise.
     */
    protected function maybeGetCachedIntegrityHash(string $src): ?string
    {
        $cacheKey   = 'sri_' . $this->createSourceIdentifier($src);
        $cacheGroup = 'wpmu_security_sri';

        $cached = $this->wpService->wpCacheGet($cacheKey, $cacheGroup);
        if ($cached !== false) {
            return $cached;
        }

        $hash = $this->generateIntegrityHash($src);
        if ($hash) {
            $this->wpService->wpCacheSet($cacheKey, $hash, $cacheGroup, WEEK_IN_SECONDS);
        }

        return $hash;
    }

    /**
     * Creates a unique identifier for the source URL.
     *
     * @param string $src The source URL of the script or style.
     * @return string A unique identifier for the source.
     */
    protected function createSourceIdentifier(string $src): string
    {
        return md5($src);
    }

    /**
     * Generates a Subresource Integrity (SRI) hash for a given source URL.
     *
     * @param string $src The source URL of the script or style.
     * @return string|null The SRI hash if the file exists and is valid, null otherwise.
     */
    protected function generateIntegrityHash(string $src): ?string
    {
        $site_url = $this->getCurrentDomain();

        if (!$this->isLocalAsset($src)) {
          return null;
        }

        $localPath = $this->createRelativePath($src);

        if (is_null($localPath) || !file_exists($localPath)) {
          return null;
        }

        $hash = base64_encode(hash_file('sha384', $localPath, true));

        return "sha384-{$hash}";
    }

    /**
     * Gets the current domain from the WordPress site.
     *
     * @return string The current domain URL.
     */
    private function getCurrentDomain(): string
    {
        return $this->wpService->getHomeUrl();
    }

    /**
     * Checks if the source matches the current domain.
     *
     * @return bool True if the source is a local asset, false otherwise.
     */
    private function isLocalAsset(string $src): bool
    {
        return strpos(
          $this->normalizeProtocol($src), 
          $this->normalizeProtocol($this->getCurrentDomain())
        ) === 0;
    }

    /**
     * Creates a relative path from the source URL. By getting the current wp-content directory
     * and removing the base URL, we can create a relative path that can be used to generate the SRI hash.
     *
     * @param string $src The source URL of the script or style.
     * @return string The relative path or null if the source is unresolvable.
     */
    private function createRelativePath(string $src): ?string
    {
        $sanitizedSrc        = $this->normalizeProtocol($src);
        $sanitizedSrc        = strtok($sanitizedSrc, '?');

        // content urls
        if(stripos($src, 'wp-content') !== false) {
            $contentUrl   = $this->normalizeProtocol(constant('WP_CONTENT_URL'));
            $sanitizedSrc =  str_replace($contentUrl, constant('WP_CONTENT_DIR'), $sanitizedSrc);
            return $sanitizedSrc;
        }

        // includes urls
        if(stripos($src, 'wp-includes') !== false) {
            $includesUrl  = $this->normalizeProtocol(
              rtrim($this->wpService->includesUrl(), '/')
            );

            $sanitizedSrc = str_replace(
              $includesUrl, 
              constant('ABSPATH') . constant('WPINC'), 
              $sanitizedSrc
            );

            return $sanitizedSrc;
        }

        return null; 
    }

    /**
     * Normalizes the protocol in the URL by removing 'http://' and 'https://'.
     *
     * @param string $url The URL to normalize.
     * @return string The normalized URL.
     */
    private function normalizeProtocol(string $url): string
    {
        return str_replace(['http://', 'https://'], '', $url);
    }
}