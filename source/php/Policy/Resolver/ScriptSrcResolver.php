<?php

namespace WPMUSecurity\Policy\Resolver;

use WPMUSecurity\Policy\DomWrapperInterface;
use WPMUSecurity\Policy\UrlInterface;

class ScriptSrcResolver implements DomainResolverInterface
{
    public function __construct(private UrlInterface $urlHelper) {}

    public function resolve(DomWrapperInterface $dom): array
    {
        $domains = [];

        foreach ($dom->query('//script[@src]') as $node) {
            if (!$node instanceof \DOMElement) {
                continue;
            }
            
            $domains[] = parse_url(
              $this->urlHelper->normalize(
                $node->getAttribute('src')
            ), PHP_URL_HOST);
        }

        // Detect inline scripts
        if ($dom->query('//script[not(@src) and normalize-space(.) != ""]')->length > 0) {
            $domains[] = "'unsafe-inline'";
        }

        return array_values(array_filter(array_unique($domains)));
    }
}