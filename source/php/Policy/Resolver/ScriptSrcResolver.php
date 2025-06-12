<?php 

namespace WPMUSecurity\Policy\Resolver;

use WPMUSecurity\Policy\DomWrapperInterface;

class ScriptSrcResolver implements DomainResolverInterface {
    public function resolve(DomWrapperInterface $dom): array {
        $domains = [];
        foreach ($dom->query('//script[@src]') as $node) {
            $domains[] = parse_url($node->getAttribute('src'), PHP_URL_HOST);
        }
        if ($dom->query('//script[not(@src) and normalize-space(.) != ""]')->length > 0) {
            $domains[] = "'unsafe-inline'";
        }
        return array_values(array_filter(array_unique($domains)));
    }
}