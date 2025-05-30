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
    public function read($markup): void
    {
        $cspPolicies    = $this->getCategorizedDomainsFromMarkup($markup);
        $cspHeader      = $this->createCategorizedCspHeader($cspPolicies);
        $this->sendCspHeaders($cspHeader);
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
     * Creates a categorized Content Security Policy header string from the provided policies.
     *
     * @param array $cspPolicies The categorized CSP policies with their respective URLs.
     * @return string The constructed categorized CSP header string.
     */
    private function createCategorizedCspHeader(array $cspPolicies): string
    {
        $csp = '';
        foreach ($cspPolicies as $policy => $urls) {
            if (!empty($urls)) {
                $csp .= "$policy 'self' " . implode(' ', $urls) . "; ";
            }
        }

        $csp .= " base-uri 'self';";
        $csp .= " form-action 'self';";
        $csp .= " upgrade-insecure-requests;";
        $csp .= " block-all-mixed-content;";
        $csp .= " require-trusted-types-for 'script';";

        return rtrim($csp, '; ');
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
            'connect-src' => [],
        ];
    
        // Scripts
        $scriptElements = $xpath->query('//script[@src]');
        foreach ($scriptElements as $script) {
            $this->addUniqueDomain($cspPolicies['script-src'], $script->getAttribute('src'));
        }
        // Check if unsafe-inline scripts are needed
        $inlineScriptElements = $xpath->query('//script[not(@src) and normalize-space(.) != ""]');
        if ($inlineScriptElements->length > 0) {
            if (!in_array("'unsafe-inline'", $cspPolicies['script-src'])) {
                $cspPolicies['script-src'][] = "'unsafe-inline'";
            }
        }
    
        //Stylesheets
        $linkElements = $xpath->query('//link[@rel="stylesheet" and @href]');
        foreach ($linkElements as $link) {
            $this->addUniqueDomain($cspPolicies['style-src'], $link->getAttribute('href'));
        }

        // Inline styles
        $styleElements = $xpath->query('//style');
        if ($styleElements->length > 0) {
            if (!in_array("'unsafe-inline'", $cspPolicies['style-src'])) {
                $cspPolicies['style-src'][] = "'unsafe-inline'";
            }
        }

        //Check if unsafe-inline styles are needed
        $allElementsWithStyleAttr = $xpath->query('//*[@style]');
        if ($allElementsWithStyleAttr->length > 0) {
             if (!in_array("'unsafe-inline'", $cspPolicies['style-src'])) {
                $cspPolicies['style-src'][] = "'unsafe-inline'";
            }
        }
    
        // Images 
        $imgElements = $xpath->query('//img[@src]');
        foreach ($imgElements as $img) {
            $this->addUniqueDomain($cspPolicies['img-src'], $img->getAttribute('src'));
        }

        // Picture
        $pictureSourceElements = $xpath->query('//picture/source[@srcset]');
        foreach ($pictureSourceElements as $source) {
            // srcset can contain multiple URLs, but for CSP it's usually just the origin we care about
            $srcset = $source->getAttribute('srcset');
            // Basic parsing for single URL in srcset for demonstration
            $urls = explode(',', $srcset);
            foreach ($urls as $urlPart) {
                $url = trim(explode(' ', $urlPart)[0]); // Get the URL before any descriptors
                $this->addUniqueDomain($cspPolicies['img-src'], $url);
            }
        }
    
        //Video and audio sources
        $mediaSourceElements = $xpath->query('//video/source[@src] | //audio/source[@src]');
        foreach ($mediaSourceElements as $source) {
            $this->addUniqueDomain($cspPolicies['media-src'], $source->getAttribute('src'));
        }
    
        // Iframes
        $iframeElements = $xpath->query('//iframe[@src]');
        foreach ($iframeElements as $iframe) {
            $this->addUniqueDomain($cspPolicies['frame-src'], $iframe->getAttribute('src'));
        }
    
        //Object and embed sources
        $objectElements = $xpath->query('//object[@data]');
        foreach ($objectElements as $object) {
            $this->addUniqueDomain($cspPolicies['object-src'], $object->getAttribute('data'));
        }
        $embedElements = $xpath->query('//embed[@src]');
        foreach ($embedElements as $embed) {
            $this->addUniqueDomain($cspPolicies['object-src'], $embed->getAttribute('src'));
        }
    
        // Form actions
        $formElements = $xpath->query('//form[@action]');
        foreach ($formElements as $form) {
            $this->addUniqueDomain($cspPolicies['form-action'], $form->getAttribute('action'));
        }
    
        // Inline fonts in style attributes
        foreach ($styleElements as $style) {
            $inlineCss = $style->nodeValue;
            preg_match_all('/url\((["\']?)(.*?)\1\)\s*format\((["\']?)(.*?)\3\)/i', $inlineCss, $matches, PREG_SET_ORDER);
            foreach ($matches as $match) {
                // Check if it's a font format
                if (preg_match('/woff|ttf|otf|eot|svg|font/', $match[4])) {
                    $this->addUniqueDomain($cspPolicies['font-src'], $match[2]);
                }
            }
        }
    
        foreach ($xpath->query('//*') as $element) {
            if ($element->hasAttributes()) {
                foreach ($element->attributes as $attr) {
                    $value = $attr->value;
                    if (filter_var($value, FILTER_VALIDATE_URL)) {
                        $this->addUniqueDomain($cspPolicies['connect-src'], $value);
                    } else {
                        if (preg_match_all('/https?:\/\/[^\s"\'>]+/i', $value, $matches)) {
                            foreach ($matches[0] as $url) {
                                if (filter_var($url, FILTER_VALIDATE_URL)) {
                                    $this->addUniqueDomain($cspPolicies['connect-src'], $url);
                                }
                            }
                        }
                    }
                }
            }
        }
    
        // Filter out empty arrays and sort URLs
        foreach ($cspPolicies as $policy => &$urls) {
            sort($urls);
            if (empty($urls)) {
                $cspPolicies[$policy] = ["'none'"];
            }
        }
        
        return $cspPolicies;
    }

    /**
     * Adds a unique domain to the provided array if it is a valid URL.
     *
     * @param array $array The array to which the domain will be added.
     * @param string $url The URL from which to extract the domain.
     */
    private function addUniqueDomain(&$array, $url) {
        if (!empty($url) && filter_var($url, FILTER_VALIDATE_URL)) {
            $host = parse_url($url, PHP_URL_HOST);
            if ($host) {
                $array[] = $host;
                $array = array_unique($array);
            }
        }
    }
}