<?php

namespace WPMUSecurity\Policy\Resolver;

/**
 * Trait for extracting host with port from URLs
 */
trait HostWithPortTrait
{
    /**
     * Extracts host with port from a URL.
     *
     * @param string $url The URL to extract host and port from
     * @return string|null The host with port (if present), or null if invalid
     */
    protected function extractHostWithPort(string $url): ?string
    {
        $parsed = parse_url($url);
        if ($parsed === false || !isset($parsed['host'])) {
            return null;
        }
        
        $host = $parsed['host'];
        if (isset($parsed['port'])) {
            $host .= ':' . $parsed['port'];
        }
        
        return $host;
    }
}