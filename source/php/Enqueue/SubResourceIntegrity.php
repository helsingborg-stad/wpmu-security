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
        $integrity = $this->generateIntegrityHash($src);
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
        $integrity = $this->generateIntegrityHash($href);

        if ($integrity) {
            $tag = str_replace(' href=', ' integrity="' . esc_attr($integrity) . '" crossorigin="anonymous" href=', $tag);
        }
        return $tag;
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

        if (strpos($src, $site_url) !== 0) {
            return null;
        }

        $relative_path = str_replace($site_url, '', $src);
        $file_path = ABSPATH . "../" . ltrim($relative_path, '/'); // TODO: Fix this path to be more robust

        if (!file_exists($file_path)) {
            return null;
        }

        // Get raw file contents and hash
        $hash = base64_encode(hash_file('sha384', $file_path, true));

        return "sha384-{$hash}";
    }

    /**
     * Gets the current domain from the WordPress site.
     *
     * @return string The current domain URL.
     */
    public function getCurrentDomain(): string
    {
        return $this->wpService->getHomeUrl();
    }
}