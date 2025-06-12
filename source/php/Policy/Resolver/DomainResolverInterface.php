<?php 

namespace WPMUSecurity\Policy\Resolver;

use WPMUSecurity\Policy\DomWrapperInterface;

interface DomainResolverInterface {
    public function resolve(DomWrapperInterface $dom): array;
}