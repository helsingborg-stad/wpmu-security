<?php 

namespace WPMUSecurity\Policy\Resolver;

use WPMUSecurity\Policy\DomWrapperInterface;

class ConnectSrcResolver implements DomainResolverInterface {
    public function resolve(DomWrapperInterface $dom): array {
        $domains = [];
        foreach ($dom->getAttributesWithUrls() as $value) {
            if (filter_var($value, FILTER_VALIDATE_URL)) {
                $domains[] = parse_url($value, PHP_URL_HOST);
            } elseif (preg_match_all('/https?:\/\/[^\s"\'>]+/i', $value, $matches)) {
                foreach ($matches[0] as $url) {
                    $domains[] = parse_url($url, PHP_URL_HOST);
                }
            }
        }
        return array_values(array_filter(array_unique($domains)));
    }
}