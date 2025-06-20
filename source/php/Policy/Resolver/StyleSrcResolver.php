<?php 

namespace WPMUSecurity\Policy\Resolver;

use WPMUSecurity\Policy\DomWrapperInterface;
use WPMUSecurity\Policy\UrlInterface;

class StyleSrcResolver implements DomainResolverInterface {

    public function __construct(private UrlInterface $urlHelper) {}

    public function resolve(DomWrapperInterface $dom): array {
        $domains = [];
        
        foreach ($dom->query('//link[@rel="stylesheet" and @href]') as $node) {
            if (!$node instanceof \DOMElement) {
                continue;
            }
            $domains[] = parse_url($this->urlHelper->normalize(
              $node->getAttribute('href')
            ), PHP_URL_HOST);
        }

        if ($dom->query('//style')->length > 0 ||$dom->query('//*[@style]')->length > 0) {
            $domains[] = "'unsafe-inline'";
        }

        return array_values(array_filter(array_unique($domains)));
    }
}