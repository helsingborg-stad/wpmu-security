<?php 

namespace WPMUSecurity\Policy\Resolver;

use WPMUSecurity\Policy\DomWrapperInterface;
use WPMUSecurity\Policy\UrlInterface;

class FormActionResolver implements DomainResolverInterface {
  
    public function __construct(private UrlInterface $urlHelper) {}

    public function resolve(DomWrapperInterface $dom): array {
        $domains = [];
        foreach ($dom->query('//form[@action]') as $node) {
            if ($node instanceof \DOMElement) {
                $domains[] = parse_url($node->getAttribute('action'), PHP_URL_HOST);
            }
        }
        return array_values(array_filter(array_unique($domains)));
    }
}