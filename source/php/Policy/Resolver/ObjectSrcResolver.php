<?php 

namespace WPMUSecurity\Policy\Resolver;

use WPMUSecurity\Policy\DomWrapperInterface;

class ObjectSrcResolver implements DomainResolverInterface {
    public function resolve(DomWrapperInterface $dom): array {
        $domains = [];
        foreach ($dom->query('//object[@data] | //embed[@src]') as $node) {
            if (!$node instanceof \DOMElement) {
                continue;
            }
            $domains[] = parse_url($node->getAttribute(
              $node->hasAttribute('data') ? 'data' : 'src'
            ), PHP_URL_HOST);
        }
        return array_values(array_filter(array_unique($domains)));
    }
}