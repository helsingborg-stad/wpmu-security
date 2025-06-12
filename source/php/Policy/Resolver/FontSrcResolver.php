<?php 

namespace WPMUSecurity\Policy\Resolver;

use WPMUSecurity\Policy\DomWrapperInterface;

class FontSrcResolver implements DomainResolverInterface {
    public function resolve(DomWrapperInterface $dom): array {
        $domains = [];
        foreach ($dom->getInlineCss() as $css) {
            preg_match_all('/url\((["\']?)(.*?)\1\)\s*format\((["\']?)(.*?)\3\)/i', $css, $matches, PREG_SET_ORDER);
            foreach ($matches as $match) {
                if (preg_match('/woff|ttf|otf|eot|svg|font/', $match[4])) {
                    $domains[] = parse_url($match[2], PHP_URL_HOST);
                }
            }
        }
        return array_values(array_filter(array_unique($domains)));
    }
}