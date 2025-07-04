<?php 

namespace WPMUSecurity\Policy\Resolver;

use WPMUSecurity\Policy\DomWrapperInterface;
use WPMUSecurity\Policy\UrlInterface;

class FontSrcResolver implements DomainResolverInterface {
    use HostWithPortTrait;
    
    public function __construct(private UrlInterface $urlHelper) {}
    
    public function resolve(DomWrapperInterface $dom): array {
        $domains = [];
        foreach ($dom->getInlineCss() as $css) {
            preg_match_all('/url\((["\']?)(.*?)\1\)\s*format\((["\']?)(.*?)\3\)/i', $css, $matches, PREG_SET_ORDER);
            foreach ($matches as $match) {
                if (preg_match('/\.(woff2?|ttf|otf|eot|svg)(\?.*)?$/i', $match[2])) {
                    $host = $this->extractHostWithPort($match[2]);
                    if ($host) {
                        $domains[] = $host;
                    }
                }
            }
        }
        $domains[] = "data:";
        return array_values(array_filter(array_unique($domains)));
    }
}