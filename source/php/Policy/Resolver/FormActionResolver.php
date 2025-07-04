<?php 

namespace WPMUSecurity\Policy\Resolver;

use WPMUSecurity\Policy\DomWrapperInterface;
use WPMUSecurity\Policy\UrlInterface;

class FormActionResolver implements DomainResolverInterface {
    use HostWithPortTrait;
  
    public function __construct(private UrlInterface $urlHelper) {}

    public function resolve(DomWrapperInterface $dom): array {
        $domains = [];
        foreach ($dom->query('//form[@action]') as $node) {
            if ($node instanceof \DOMElement) {
                $action = $node->getAttribute('action');
                $host = $this->extractHostWithPort($action);
                if ($host) {
                    $domains[] = $host;
                }
            }
        }
        $domains[] = "'self'";
        return array_values(array_filter(array_unique($domains)));
    }
}