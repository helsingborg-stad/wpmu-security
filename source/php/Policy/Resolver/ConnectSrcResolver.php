<?php 

namespace WPMUSecurity\Policy\Resolver;

use WPMUSecurity\Policy\DomWrapperInterface;
use WPMUSecurity\Policy\UrlInterface;

class ConnectSrcResolver implements DomainResolverInterface {
  use HostWithPortTrait;

  public function __construct(private UrlInterface $urlHelper) {}

  public function resolve(DomWrapperInterface $dom): array {
      return array_values(array_unique(
          array_merge(
              $this->getUrlsFromInlineScripts($dom),
              $this->getUrlsFromArbitraryAttributes($dom)
          )
      ));
  }

  private function getUrlsFromArbitraryAttributes($dom) {

    $domains = [];

      foreach ($dom->getAttributesWithUrls() as $attr) {
          if (!$attr instanceof \DOMAttr || $attr->name === 'href') {
              continue;
          }

          // Normalize the value to handle escaped slashes
          $value = $this->urlHelper->normalize($attr->value);

          //Regex match for URLs
          if (preg_match_all('/https?:\/\/[^\s"\'>]+/i', $value, $matches)) {
              foreach ($matches[0] as $url) {
                  $host = $this->extractHostWithPort($url);
                  if ($host) {
                      $domains[] = $host;
                  }
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
  private function getUrlsFromInlineScripts($dom) {
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