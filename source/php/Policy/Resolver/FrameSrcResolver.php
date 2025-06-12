<?php 

namespace WPMUSecurity\Policy\Resolver;

use WPMUSecurity\Policy\DomWrapperInterface;
use WPMUSecurity\Policy\UrlInterface;

class FrameSrcResolver implements DomainResolverInterface {

    public function __construct(private UrlInterface $urlHelper) {}

    public function resolve(DomWrapperInterface $dom): array {
        $domains = [];
        foreach ($dom->query('//iframe[@src]') as $node) {
            if (!$node instanceof \DOMElement) {
                continue;
            }
            $domains[] = parse_url($node->getAttribute('src'), PHP_URL_HOST);
        }
        return array_values(array_filter(array_unique($domains)));
    }
}