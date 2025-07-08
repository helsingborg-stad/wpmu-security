<?php 

namespace WPMUSecurity\Policy\Resolver;

use WPMUSecurity\Policy\DomWrapperInterface;
use WPMUSecurity\Policy\UrlInterface;

class DefaultResolver implements DomainResolverInterface {
    public function __construct(private UrlInterface $urlHelper) {}
    public function resolve(DomWrapperInterface $dom): array {
        return ["'none'"];
    }
}