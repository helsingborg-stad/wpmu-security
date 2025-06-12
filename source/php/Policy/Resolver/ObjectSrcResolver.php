<?php 

namespace WPMUSecurity\Policy\Resolver;

use WPMUSecurity\Policy\DomWrapperInterface;

class ObjectSrcResolver implements DomainResolverInterface {
    public function resolve(DomWrapperInterface $dom): array {
        $domains = [];
        foreach ($dom->query('//object[@data] | //embed[@src]') as $node) {
            $attr = $node->hasAttribute('data') ? 'data' : 'src';
            $domains[] = parse_url($node->getAttribute($attr), PHP_URL_HOST);
        }
        return array_values(array_filter(array_unique($domains)));
    }
}