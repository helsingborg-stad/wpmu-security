<?php

namespace WPMUSecurity\Policy;

use WpService\WpService;
use DOMDocument;
use WPMUSecurity\Policy\DomWrapper;
use WPMUSecurity\Policy\Resolver\ScriptSrcResolver;
use WPMUSecurity\Policy\Resolver\StyleSrcResolver;
use WPMUSecurity\Policy\Resolver\ImgSrcResolver;
use WPMUSecurity\Policy\Resolver\MediaSrcResolver;
use WPMUSecurity\Policy\Resolver\FrameSrcResolver;
use WPMUSecurity\Policy\Resolver\ObjectSrcResolver;
use WPMUSecurity\Policy\Resolver\FormActionResolver;
use WPMUSecurity\Policy\Resolver\FontSrcResolver;
use WPMUSecurity\Policy\Resolver\ConnectSrcResolver;

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
    public function createCategorizedCspHeader(array $cspPolicies): string
    {
        $csp = '';
        foreach ($cspPolicies as $policy => $domains) {
            if (!empty($domains)) {

                $implodedDomains = array_map(function ($domain) {
                    return trim($domain);
                }, $domains);
                $implodedDomains = implode(' ', $implodedDomains);

                $csp .= "$policy " . $implodedDomains . "; ";
            }
        }

        $csp .= " base-uri 'self';";
        $csp .= " upgrade-insecure-requests;";
        $csp .= " block-all-mixed-content;";

        return rtrim($csp, '; ');
    }

    /**
     * Extracts and categorizes domains from the provided HTML markup using resolvers.
     *
     * @param string $html The HTML markup to search for domains.
     * @return array An associative array with categorized domains.
     */
    public function getCategorizedDomainsFromMarkup($html): array {
        $dom = new DOMDocument();

        @$dom->loadHTML($html);
        $wrapper = new DomWrapper($dom);
        $urlHelper = new \WPMUSecurity\Policy\Url();

        $resolvers = [
            'script-src'    => new ScriptSrcResolver($urlHelper),
            'style-src'     => new StyleSrcResolver($urlHelper),
            'img-src'       => new ImgSrcResolver($urlHelper),
            'media-src'     => new MediaSrcResolver($urlHelper),
            'frame-src'     => new FrameSrcResolver($urlHelper),
            'object-src'    => new ObjectSrcResolver($urlHelper),
            'form-action'   => new FormActionResolver($urlHelper),
            'font-src'      => new FontSrcResolver($urlHelper),
            'connect-src'   => new ConnectSrcResolver($urlHelper),
        ];

        $cspPolicies = [];
        foreach ($resolvers as $policy => $resolver) {
            $resolvedValue          = $resolver->resolve($wrapper);
            $cspPolicies[$policy]   = empty($resolvedValue) ? ["'none'"] : $resolvedValue;
        }
        return $this->wpService->applyFilters('WpSecurity/Csp', $cspPolicies);
    }
}