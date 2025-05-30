<?php

namespace WPMUSecurity\Policy;

use WP;
use WpService\WpService;
use DOMDocument;
use DOMXPath;

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
    public function getCategorizedDomainsFromMarkup($html) {
        $dom = new DOMDocument();
        // Suppress warnings for malformed HTML
        @$dom->loadHTML($html);
        $xpath = new DOMXPath($dom);
    
        $cspPolicies = [
            'script-src' => [],
            'style-src' => [],
            'img-src' => [],
            'media-src' => [],
            'frame-src' => [],
            'object-src' => [],
            'form-action' => [],
            'font-src' => [],
            'connect-src' => [], // For data attributes that might imply a connection
        ];
    
        // Helper to add unique domains (hosts) to a policy array
        function addUniqueDomain(&$array, $url) {
            if (!empty($url) && filter_var($url, FILTER_VALIDATE_URL)) {
                $host = parse_url($url, PHP_URL_HOST);
                if ($host) {
                    $array[] = $host;
                    $array = array_unique($array);
                }
            }
        }
    
        // script-src
        // External scripts
        $scriptElements = $xpath->query('//script[@src]');
        foreach ($scriptElements as $script) {
            addUniqueDomain($cspPolicies['script-src'], $script->getAttribute('src'));
        }
        // Inline scripts are 'unsafe-inline' and don't have a source, but we can note their presence
        $inlineScriptElements = $xpath->query('//script[not(@src) and normalize-space(.) != ""]');
        if ($inlineScriptElements->length > 0) {
            if (!in_array("'unsafe-inline'", $cspPolicies['script-src'])) {
                $cspPolicies['script-src'][] = "'unsafe-inline'";
            }
        }
    
        // style-src
        // External stylesheets
        $linkElements = $xpath->query('//link[@rel="stylesheet" and @href]');
        foreach ($linkElements as $link) {
            addUniqueDomain($cspPolicies['style-src'], $link->getAttribute('href'));
        }
        // Inline styles
        $styleElements = $xpath->query('//style');
        if ($styleElements->length > 0) {
            if (!in_array("'unsafe-inline'", $cspPolicies['style-src'])) {
                $cspPolicies['style-src'][] = "'unsafe-inline'";
            }
        }
        // Check for inline styles in style attributes (less common for CSP direct impact but good for completeness)
        $allElementsWithStyleAttr = $xpath->query('//*[@style]');
        if ($allElementsWithStyleAttr->length > 0) {
             if (!in_array("'unsafe-inline'", $cspPolicies['style-src'])) {
                $cspPolicies['style-src'][] = "'unsafe-inline'";
            }
        }
    
    
        // img-src
        $imgElements = $xpath->query('//img[@src]');
        foreach ($imgElements as $img) {
            addUniqueDomain($cspPolicies['img-src'], $img->getAttribute('src'));
        }
        // Picture source srcset
        $pictureSourceElements = $xpath->query('//picture/source[@srcset]');
        foreach ($pictureSourceElements as $source) {
            // srcset can contain multiple URLs, but for CSP it's usually just the origin we care about
            $srcset = $source->getAttribute('srcset');
            // Basic parsing for single URL in srcset for demonstration
            $urls = explode(',', $srcset);
            foreach ($urls as $urlPart) {
                $url = trim(explode(' ', $urlPart)[0]); // Get the URL before any descriptors
                addUniqueDomain($cspPolicies['img-src'], $url);
            }
        }
    
    
        // media-src (video and audio)
        $mediaSourceElements = $xpath->query('//video/source[@src] | //audio/source[@src]');
        foreach ($mediaSourceElements as $source) {
            addUniqueDomain($cspPolicies['media-src'], $source->getAttribute('src'));
        }
        $videoElements = $xpath->query('//video[@src]'); // Direct video src
        foreach ($videoElements as $video) {
            addUniqueDomain($cspPolicies['media-src'], $video->getAttribute('src'));
        }
        $audioElements = $xpath->query('//audio[@src]'); // Direct audio src
        foreach ($audioElements as $audio) {
            addUniqueDomain($cspPolicies['media-src'], $audio->getAttribute('src'));
        }
    
    
        // frame-src
        $iframeElements = $xpath->query('//iframe[@src]');
        foreach ($iframeElements as $iframe) {
            addUniqueDomain($cspPolicies['frame-src'], $iframe->getAttribute('src'));
        }
    
    
        // object-src
        $objectElements = $xpath->query('//object[@data]');
        foreach ($objectElements as $object) {
            addUniqueDomain($cspPolicies['object-src'], $object->getAttribute('data'));
        }
        $embedElements = $xpath->query('//embed[@src]');
        foreach ($embedElements as $embed) {
            addUniqueDomain($cspPolicies['object-src'], $embed->getAttribute('src'));
        }
    
    
        // form-action
        $formElements = $xpath->query('//form[@action]');
        foreach ($formElements as $form) {
            addUniqueDomain($cspPolicies['form-action'], $form->getAttribute('action'));
        }
    
        // font-src
        // For webfonts defined in inline styles, we need to parse the CSS
        foreach ($styleElements as $style) {
            $inlineCss = $style->nodeValue;
            preg_match_all('/url\((["\']?)(.*?)\1\)\s*format\((["\']?)(.*?)\3\)/i', $inlineCss, $matches, PREG_SET_ORDER);
            foreach ($matches as $match) {
                // Check if it's a font format
                if (preg_match('/woff|ttf|otf|eot|svg|font/', $match[4])) {
                    addUniqueDomain($cspPolicies['font-src'], $match[2]);
                }
            }
        }
    
        // connect-src (for URLs found in data attributes that might imply a connection)
        // data-link, data-json, data-serialized
        $dataElements = $xpath->query('//*[@data-link | @data-json | @data-serialized]');
        foreach ($dataElements as $element) {
            if ($element->hasAttribute('data-link')) {
                addUniqueDomain($cspPolicies['connect-src'], $element->getAttribute('data-link'));
            }
            if ($element->hasAttribute('data-json')) {
                $jsonData = json_decode($element->getAttribute('data-json'), true);
                if (is_array($jsonData)) {
                    foreach ($jsonData as $key => $value) {
                        if (is_string($value)) {
                            addUniqueDomain($cspPolicies['connect-src'], $value);
                        }
                    }
                }
            }
            if ($element->hasAttribute('data-serialized')) {
                // Attempt to unserialize PHP data
                $serializedData = @unserialize($element->getAttribute('data-serialized'));
                if ($serializedData !== false && is_array($serializedData)) {
                    foreach ($serializedData as $key => $value) {
                        if (is_string($value)) {
                            addUniqueDomain($cspPolicies['connect-src'], $value);
                        }
                    }
                }
            }
        }
    
        // Filter out empty arrays and sort URLs
        foreach ($cspPolicies as $policy => &$urls) {
            sort($urls); // Sort URLs alphabetically for consistent output
            if (empty($urls)) {
                unset($cspPolicies[$policy]);
            }
        }
    
        var_dump($cspPolicies);

        return $cspPolicies;
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