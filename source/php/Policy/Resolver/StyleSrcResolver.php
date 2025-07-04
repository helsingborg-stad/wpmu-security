<?php 

namespace WPMUSecurity\Policy\Resolver;

use WPMUSecurity\Policy\DomWrapperInterface;
use WPMUSecurity\Policy\UrlInterface;

class StyleSrcResolver implements DomainResolverInterface {
    use HostWithPortTrait;

    public function __construct(private UrlInterface $urlHelper) {}

    public function resolve(DomWrapperInterface $dom): array {
        $domains = [];
        
        foreach ($dom->query('//link[@rel="stylesheet" and @href]') as $node) {
            if (!$node instanceof \DOMElement) {
                continue;
            }
            $normalizedUrl = $this->urlHelper->normalize($node->getAttribute('href'));
            if ($normalizedUrl) {
                $host = $this->extractHostWithPort($normalizedUrl);
                if ($host) {
                    $domains[] = $host;
                }
            }
        }

        if ($dom->query('//style')->length > 0 ||$dom->query('//*[@style]')->length > 0) {
            $domains[] = "'unsafe-inline'";
        }

        return array_values(array_filter(array_unique($domains)));
    }
}