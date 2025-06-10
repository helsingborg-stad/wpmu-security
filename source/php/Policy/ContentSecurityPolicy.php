<?php

namespace WPMUSecurity\Policy;

use WP;
use WpService\WpService;

/**
 * Class ContentSecurityPolicy
 *
 * This class is responsible for generating and sending Content Security Policy (CSP) headers
 * based on the domains found in the HTML markup, localized scripts, and WordPress content directories.
 * 
 * It is only compatible with Themes implementing a filter that allows reading the output markup.
 */
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
        //$this->wpService->addFilter('Website/HTML/output', [$this, 'read'], 10, 1);
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
            $csp .= " style-src 'self' 'unsafe-inline' " . implode(' ', $domains) . ";";
            $csp .= " img-src 'self' data: " . implode(' ', $domains) . ";";
            $csp .= " connect-src 'self' " . implode(' ', $domains) . ";";
            $csp .= " font-src 'self' " . implode(' ', $domains) . ";";
            $csp .= " frame-ancestors 'self' " . implode(' ', $domains) . ";";
            $csp .= " object-src 'self' " . implode(' ', $domains) . ";";
            $csp .= " base-uri 'self';";
            $csp .= " form-action 'self';";
            $csp .= " upgrade-insecure-requests;";
            $csp .= " block-all-mixed-content;";
        }
        return $csp;
    }

    /**
     * Extracts unique domains from the provided HTML markup.
     *
     * @param string $markup The HTML markup to search for domains.
     * @return array An array of unique domain names found in the markup.
     */
    public function getDomainsFromMarkup($markup): array
    {
        // Remove all anchor elements to ignore their href values
        $markupWithoutAnchors = preg_replace('/<a\b[^>]*>.*?<\/a>/is', '', $markup);

        $domains = [];
        preg_match_all(self::LINK_REGEX, $markupWithoutAnchors, $matches);
        if (isset($matches[1])) {
            $domains = array_unique($matches[1]);
        }
        return $domains;
    }


    /**
     * Extracts and categorizes domains from the provided HTML markup.
     *
     * This method categorizes domains into scripts, styles, images, and others
     * based on their file extensions. 
     *
     * @param string $markup The HTML markup to search for domains.
     * @return array An associative array with categorized domains.
     */
    public function getCategorizedDomainsFromMarkup($markup): array
    {
        $domains = [
            'scripts' => [],
            'styles' => [],
            'images' => [],
            'fonts' => [],
            'others' => []
        ];

        $markupWithoutAnchors = preg_replace('/<a\b[^>]*>.*?<\/a>/is', '', $markup);
        preg_match_all(self::LINK_REGEX, $markupWithoutAnchors, $matches);
        if (isset($matches[1])) {
            foreach ($matches[1] as $domain) {
                $parsedUrl = parse_url($domain);
                if (isset($parsedUrl['path'])) {
                    $path = $parsedUrl['path'];
                    $extension = pathinfo($path, PATHINFO_EXTENSION);
                    switch ($extension) {
                        case 'js':
                            $domains['scripts'][] = $domain;
                            break;
                        case 'css':
                            $domains['styles'][] = $domain;
                            break;
                        case 'jpg':
                        case 'jpeg':
                        case 'png':
                        case 'gif':
                        case 'webp':
                            $domains['images'][] = $domain;
                            break;
                        case 'woff':
                        case 'woff2':
                        case 'ttf':
                            $domains['fonts'][] = $domain;
                            break;
                        default:
                            $domains['others'][] = $domain;
                    }
                }
            }
        }

        return array_map('array_unique', $domains);
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