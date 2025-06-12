<?php 

namespace WPMUSecurity\Policy\Resolver;

use WPMUSecurity\Policy\DomWrapperInterface;
use WPMUSecurity\Policy\UrlInterface;

class ConnectSrcResolver implements DomainResolverInterface {

  public function __construct(private UrlInterface $urlHelper) {}

  public function resolve(DomWrapperInterface $dom): array {
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
                  $domains[] = parse_url($url, PHP_URL_HOST);
              }
          }
      }

      return array_values(array_filter(array_unique($domains)));
  }
}