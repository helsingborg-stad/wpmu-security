<?php 

namespace WPMUSecurity\Policy\Resolver;

use WPMUSecurity\Policy\DomWrapperInterface;
use WPMUSecurity\Policy\UrlInterface;

class MediaSrcResolver implements DomainResolverInterface {
    use HostWithPortTrait;

    public function __construct(private UrlInterface $urlHelper) {}

    public function resolve(DomWrapperInterface $dom): array {
        $domains = [];
        foreach ($dom->query('//video[@src] | //video/source[@src] | //audio[@src] | //audio/source[@src]') as $node) {
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
        $domains[] = "blob:";
        return array_values(array_filter(array_unique($domains)));
    }
}