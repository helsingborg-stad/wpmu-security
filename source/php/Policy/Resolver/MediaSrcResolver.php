<?php 

namespace WPMUSecurity\Policy\Resolver;

use WPMUSecurity\Policy\DomWrapperInterface;

class MediaSrcResolver implements DomainResolverInterface {
    public function resolve(DomWrapperInterface $dom): array {
        $domains = [];
        foreach ($dom->query('//video/source[@src] | //audio/source[@src]') as $node) {
            $domains[] = parse_url($node->getAttribute('src'), PHP_URL_HOST);
        }
        return array_values(array_filter(array_unique($domains)));
    }
}