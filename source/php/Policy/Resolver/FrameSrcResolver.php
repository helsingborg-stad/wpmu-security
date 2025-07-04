<?php 

namespace WPMUSecurity\Policy\Resolver;

use WPMUSecurity\Policy\DomWrapperInterface;
use WPMUSecurity\Policy\UrlInterface;

class FrameSrcResolver implements DomainResolverInterface {
    use HostWithPortTrait;

    public function __construct(private UrlInterface $urlHelper) {}

    public function resolve(DomWrapperInterface $dom): array {
        $domains = [];
        foreach ($dom->query('//iframe[@src]') as $node) {
            if (!$node instanceof \DOMElement) {
                continue;
            }
            $src = $node->getAttribute('src');
            $host = $this->extractHostWithPort($src);
            if ($host) {
                $domains[] = $host;
            }
        }
        $domains[] = "'self'";
        return array_values(array_filter(array_unique($domains)));
    }
}