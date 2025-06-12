<?php 

namespace WPMUSecurity\Policy\Resolver;

use WPMUSecurity\Policy\DomWrapperInterface;

class ImgSrcResolver implements DomainResolverInterface {
    public function resolve(DomWrapperInterface $dom): array {
        $domains = [];
        foreach ($dom->query('//img[@src]') as $node) {

          if (!$node instanceof \DOMElement) {
            continue;
        } 

            $domains[] = parse_url($node->getAttribute('src'), PHP_URL_HOST);
        }
        foreach ($dom->query('//picture/source[@srcset]') as $source) {
            if (!$source instanceof \DOMElement) {
                continue;
            }
            $urls = explode(',', $source->getAttribute('srcset'));
            foreach ($urls as $urlPart) {
                $url = trim(explode(' ', $urlPart)[0]);
                $domains[] = parse_url($url, PHP_URL_HOST);
            }
        }
        return array_values(array_filter(array_unique($domains)));
    }
}