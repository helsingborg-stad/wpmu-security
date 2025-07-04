<?php 

namespace WPMUSecurity\Policy\Resolver;

use WPMUSecurity\Policy\DomWrapperInterface;
use WPMUSecurity\Policy\UrlInterface;

class ObjectSrcResolver implements DomainResolverInterface {
    use HostWithPortTrait;

    public function __construct(private UrlInterface $urlHelper) {}

    public function resolve(DomWrapperInterface $dom): array {
        $domains = [];
        foreach ($dom->query('//object[@data] | //embed[@src]') as $node) {
            if (!$node instanceof \DOMElement) {
                continue;
            }
            $url = $node->getAttribute(
              $node->hasAttribute('data') ? 'data' : 'src'
            );
            $host = $this->extractHostWithPort($url);
            if ($host) {
                $domains[] = $host;
            }
        }
        return array_values(array_filter(array_unique($domains)));
    }
}