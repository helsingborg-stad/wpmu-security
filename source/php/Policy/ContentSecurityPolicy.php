<?php

namespace WPMUSecurity\Policy;

use WP;
use WpService\WpService;

class ContentSecurityPolicy
{
    const LINK_REGEX = '/https?:\\\\?\/\\\\?\/([a-z0-9.-]+)/i';

    public function __construct(private WpService $wpService){}

    /**
     * Adds hooks for generating and sending Content Security Policy (CSP) headers.
     *
     * @return void
     */
    public function addHooks(): void
    {
        //If current theme is municipio, do not run
        //if ($this->wpService->getCurrentTheme() === 'municipio') {
          //return;
        //}
        $this->wpService->addFilter('Municipio/blade/output', [$this, 'read'], 10, 1);
    }

    /**
     * Reads the markup and extracts domains to create a CSP header.
     *
     * @param string $markup The HTML markup to process.
     * @return string The original markup with CSP headers sent.
     */
    public function read($markup): string
    {
        $domains = $this->getDomainsFromMarkup($markup);
        $domains = array_merge(
            $domains,
            $this->getDomainsFromLocalizedScripts(),
            $this->getContentDomains()
        );

        $domains = array_unique($domains);
        $domains = array_filter($domains);

        //var_dump($domains);

        if (!empty($domains)) {
          $this->sendCspHeaders(
            $this->createCspHeader($domains)
          );
        }
        return $markup;
    }

    /**
     * Sends the Content Security Policy headers if not already sent.
     *
     * @param string $cspHeader The CSP header to send.
     * @return void
     */
    public function sendCspHeaders($cspHeader): void
    {
        foreach (headers_list() as $header) {
            if (stripos($header, 'Content-Security-Policy:') === 0) {
                return;
            }
        }
        if (!headers_sent()) {
            header('Content-Security-Policy: ' . $cspHeader);
        }
    }

    /**
     * Creates a Content Security Policy header string from the provided domains.
     *
     * @param array $domains The list of domains to include in the CSP header.
     * @return string The constructed CSP header string.
     */
    private function createCspHeader(array $domains): string
    {
        $csp = "default-src 'self';";
        if (!empty($domains)) {
            $csp .= " script-src 'self' 'unsafe-inline' " . implode(' ', $domains) . ";";
        }
        return $csp;
    }

    /**
     * Extracts unique domains from the provided HTML markup.
     *
     * @param string $markup The HTML markup to search for domains.
     * @return array An array of unique domain names found in the markup.
     */
    private function getDomainsFromMarkup($markup): array
    {
        $domains = [];
        preg_match_all(self::LINK_REGEX, $markup, $matches);
        if (isset($matches[1])) {
            $domains = array_unique($matches[1]);
        }
        return $domains;
    }

    /**
     * Extracts domains from localized scripts registered in WordPress.
     *
     * This method checks both the 'extra' data of scripts and their localizations
     * to find any URLs that match the defined regex pattern.
     *
     * @return array An array of unique domain names found in localized scripts.
     */
    public function getDomainsFromLocalizedScripts(): array
    {
        $domains = [];
        $scripts = wp_scripts()->registered ?? [];

        foreach ($scripts as $script) {
            // Check 'localize' data
            if (!empty($script->extra['data'])) {

                if($jsonDecoded = json_decode($script->extra['data'])) {
                  $script->extra['data'] = $jsonDecoded;
                }

                preg_match_all(self::LINK_REGEX, $script->extra['data'], $matches);
                if (!empty($matches[1])) {
                    $domains = array_merge($domains, $matches[1]);
                }
            }

            // Check directly localized data
            if (!empty($script->localizations)) {
                foreach ($script->localizations as $localization) {
                    $json = wp_json_encode($localization);
                    preg_match_all(self::LINK_REGEX, $json, $matches);
                    if (!empty($matches[1])) {
                        $domains = array_merge($domains, $matches[1]);
                    }
                }
            }
        }

        return $domains;
    }

    /**
     * Gets the wp-content domains for the current WordPress site.
     *
     * @return arrat An array of unique domain names for the wp-content directory.
     */
    public function getContentDomains() : array
    {
        $domains = $this->wpService->wpUploadDir();

        $domains = array_reduce(
            $domains,
            function ($carry, $item) {
                if (isset($item['baseurl'])) {
                    $carry[] = parse_url($item['baseurl'])['host'] ?? null;
                }
                return $carry;
            },
            []
        );

        return array_filter($domains);
    }
}