<?php

namespace WPMUSecurity\Policy\Resolver;

use WPMUSecurity\Policy\DomWrapperInterface;
use WPMUSecurity\Policy\UrlInterface;

class ScriptSrcResolver implements DomainResolverInterface
{
    use HostWithPortTrait;

    public function __construct(private UrlInterface $urlHelper) {}

    public function resolve(DomWrapperInterface $dom): array
    {
        $domains = [];

        //Allow 'unsafe-eval'
        $domains[] = $this->setUnsafeEval();

        // Detect inline scripts
        $unsafeInline = $this->setUnsafeInline($dom);

        //Parse inline scripts
        if($unsafeInline !== null) {
          $domains[] = $unsafeInline;
          array_push($domains, ...$this->getUrlsFromInlineScripts($dom));
        }
        
        //Script src
        array_push($domains, ...$this->getUrlsFromScriptSrc($dom));
        
        //Clean up and normalize domains
        return array_values(array_filter(array_unique($domains)));
    }

    /**
     * Sets 'unsafe-inline' if there are inline scripts present.
     *
     * @param DomWrapperInterface $dom
     * @return string|null
     */
    private function setUnsafeInline($dom): ?string {
        // Check for inline scripts
        if ($dom->query('//script[not(@src) and normalize-space(.) != ""]')->length > 0) {
            return "'unsafe-inline'";
        }
        return null;
    }

    /**
     * Sets 'unsafe-eval'
     * @return string
     */
    private function setUnsafeEval(): ?string {
        return "'unsafe-eval'";
    }

    /**
     * Extracts URLs from <script src="URL"> tags.
     *
     * @param DomWrapperInterface $dom
     * @return array
     */
    private function getUrlsFromScriptSrc($dom): array {
        $domains = [];

        foreach ($dom->query('//script[@src]') as $node) {
            if (!$node instanceof \DOMElement) {
                continue;
            }

            $normalizedUrl = $this->urlHelper->normalize($node->getAttribute('src'));
            if ($normalizedUrl) {
                $host = $this->extractHostWithPort($normalizedUrl);
                if ($host) {
                    $domains[] = $host;
                }
            }
        }

        return array_values(array_filter(array_unique($domains)));
    }

    /**
     * Extracts URLs from <script> URLS HERE </script> tags, including inline scripts.
     *
     * @param DomWrapperInterface $dom
     * @return array
     */
    private function getUrlsFromInlineScripts($dom): array
    {
      $domains = [];

      foreach ($dom->query('//script') as $node) {
          if (!$node instanceof \DOMElement) {
              continue;
          }

          if (!$node->hasAttribute('src') && trim($node->textContent) !== '') {
              if (preg_match_all('/https?:\\\\?\/\\\\?\/[^\s"\'>\\\\]+/i', $node->textContent, $matches)) {
                  foreach ($matches[0] as $url) {
                      $normalizedUrl = $this->urlHelper->normalize($url);
                      if ($normalizedUrl) {
                          $host = $this->extractHostWithPort($normalizedUrl);
                          if ($host) {
                              $domains[] = $host;
                          }
                      }
                  }
              }
          }

      }

      return array_values(array_filter(array_unique($domains)));
    }
}