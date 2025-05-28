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
    const LINK_REGEX = '/<(script|img|link|iframe|source|form|video|audio|object|embed|frame)[^>]+(?:src|href|data|action)=["\']https?:\/\/([a-z0-9.-]+)/i';

    public function __construct(private WpService $wpService){}

    /**
     * Adds hooks for generating and sending Content Security Policy (CSP) headers.
     *
     * @return void
     */
    public function addHooks(): void
    {
        $this->wpService->addFilter('Website/HTML/output', [$this, 'read'], 10, 1); 
    }

    /**
     * Reads the markup and extracts domains to create a CSP header.
     *
     * @param string $markup The HTML markup to process.
     * @return string The original markup with CSP headers sent.
     */
    public function read($markup): string
    {
        $categorized = $this->getDomainsFromMarkup($markup);

        $extra = array_merge(
            $this->getDomainsFromLocalizedScripts(),
            $this->getContentDomains()
        );

        foreach ($categorized as &$domains) {
            $domains = array_unique(array_merge($domains, $extra));
        }

        if (!empty(array_filter($categorized))) {
            $this->sendCspHeaders(
                $this->createCspHeader($categorized)
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
     * @param array $categorizedDomains The list of categorized domains to include in the CSP header.
     * @return string The constructed CSP header string.
     */
    private function createCspHeader(array $categorizedDomains): string
    {
        $csp = "default-src 'self';";

        $directives = [
            'script-src' => "'self' 'unsafe-inline'",
            'style-src' => "'self' 'unsafe-inline'",
            'img-src' => "'self' data:",
            'connect-src' => "'self'",
            'font-src' => "'self'",
        ];

        foreach ($directives as $directive => $default) {
            $domains = $categorizedDomains[$directive] ?? [];
            $csp .= " {$directive} {$default} " . implode(' ', $domains) . ";";
        }

        $csp .= " object-src 'none';";
        $csp .= " frame-ancestors 'none';";
        $csp .= " base-uri 'self';";
        $csp .= " form-action 'self';";
        $csp .= " upgrade-insecure-requests;";
        $csp .= " block-all-mixed-content;";

        return $csp;
    }

    /**
     * Extracts unique domains from the provided HTML markup.
     *
     * @param string $markup The HTML markup to search for domains.
     * @return array An array of categorized domain names found in the markup.
     */
    private function getDomainsFromMarkup($markup): array
    {
        $categories = [
            'script-src' => [],
            'img-src' => [],
            'style-src' => [],
            'connect-src' => [],
            'font-src' => [],
        ];

        $dataAttributesToCspCategory = [
            'connect-src' => ['data-src'],
            'frame-src' => ['data-src'],
        ];

        // Match element attributes (src, href, etc.)
        preg_match_all(self::LINK_REGEX, $markup, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            [$full, $tag, $domain] = $match;
            $domain = strtolower($domain);
            switch ($tag) {
                case 'script':
                    $categories['script-src'][] = $domain;
                    break;
                case 'img':
                case 'source':
                case 'video':
                case 'audio':
                case 'object':
                case 'embed':
                    $categories['img-src'][] = $domain;
                    break;
                case 'link':
                    $categories['style-src'][] = $domain;
                    break;
                case 'iframe':
                case 'frame':
                case 'form':
                    $categories['connect-src'][] = $domain;
                    break;
                case 'font':
                    $categories['font-src'][] = $domain;
                    break;
            }
        }

        if (preg_match_all('/<script[^>]*>(.*?)<\/script>/is', $markup, $scriptMatches)) {
            foreach ($scriptMatches[1] as $scriptContent) {
                $scriptContent = str_replace('\/', '/', $scriptContent);
                if (preg_match_all('/https?:\/\/([a-z0-9.-]+)/i', $scriptContent, $jsonMatches)) {
                    $categories['img-src'] = array_merge($categories['img-src'], $jsonMatches[1]);
                }
            }
        }

        foreach ($dataAttributesToCspCategory as $category => $attributes) {
            foreach ($attributes as $attr) {
                $pattern = '/'.preg_quote($attr, '/').'=["\']\[(.*?)\]["\']/i';
                if (preg_match_all($pattern, $markup, $attrMatches)) {
                    foreach ($attrMatches[1] as $jsonString) {
                        $decoded = html_entity_decode($jsonString, ENT_QUOTES);
                        $urls = json_decode($decoded, true);
                        if (is_array($urls)) {
                            foreach ($urls as $url) {
                                if (preg_match('/https?:\/\/([a-z0-9.-]+)/i', $url, $urlMatch)) {
                                    $categories[$category][] = strtolower($urlMatch[1]);
                                }
                            }
                        }
                    }
                }
            }
        }

        foreach ($categories as $key => $domains) {
            $categories[$key] = array_unique($domains);
        }

        return $categories;
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
                if(preg_match('/^https?:\/\//i', $item)) {
                    $carry[] = parse_url($item)['host'] ?? null;
                }
                return $carry;
            },
            []
        );

        return array_filter($domains);
    }
}