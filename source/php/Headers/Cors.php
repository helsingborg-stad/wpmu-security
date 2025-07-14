<?php

namespace WPMUSecurity\Headers;

use WpService\WpService;

class Cors
{
    public function __construct(private WpService $wpService){}

    /**
     * Adds hooks for the password reset functionality.
     *
     * @return void
     */
    public function addHooks(): void
    {
      $this->wpService->addAction('send_headers', [$this, 'addCorsHeaders']);
    }

    /**
     * Adds CORS headers to the response.
     * This allows cross-origin requests from configured domains.
     * It checks if the headers are already set to avoid duplicates.
     * If not set, it adds the Access-Control-Allow-Origin header with the appropriate origin.
     */
    public function addCorsHeaders(): void
    {
      foreach (headers_list() as $header) {
        if (stripos($header, 'Access-Control-Allow-Origin:') === 0) {
          return;
        }
      }
      
      if (!headers_sent()) {
        $allowedOrigins = $this->getAllowedOrigins();
        $origin = $this->getRequestOrigin();
        
        if ($this->isOriginAllowed($origin, $allowedOrigins)) {
          header('Access-Control-Allow-Origin: ' . $origin);
          header('Access-Control-Allow-Credentials: true');
          header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
          header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
        } else {
          // Fallback to current domain for backward compatibility
          header('Access-Control-Allow-Origin: ' . $this->getHomeUrl());
        }
      }      
    }

    /**
     * Gets all allowed origins including current domain and custom origins.
     *
     * @return array The allowed origins.
     */
    private function getAllowedOrigins(): array
    {
      $origins = [$this->getHomeUrl()];
      
      // Check if subdomain support is enabled for current domain
      $subdomainSupport = $this->wpService->getOption('security_cors_subdomain_support', false);
      if ($subdomainSupport) {
        // Add wildcard version of current domain
        $currentDomain = $this->getHomeUrl();
        $origins[] = $this->addWildcardToCurrentDomain($currentDomain);
      }
      
      // Apply filter to allow custom origins
      $origins = $this->wpService->applyFilters('WpSecurity/Cors', $origins);
      
      return array_unique($origins);
    }

    /**
     * Gets the origin from the current request.
     *
     * @return string|null The request origin or null if not set.
     */
    private function getRequestOrigin(): ?string
    {
      return $_SERVER['HTTP_ORIGIN'] ?? null;
    }

    /**
     * Checks if the given origin is allowed.
     *
     * @param string|null $origin The origin to check.
     * @param array $allowedOrigins The list of allowed origins.
     * @return bool Whether the origin is allowed.
     */
    private function isOriginAllowed(?string $origin, array $allowedOrigins): bool
    {
      if (empty($origin)) {
        return false;
      }

      foreach ($allowedOrigins as $allowedOrigin) {
        if ($this->matchesOrigin($origin, $allowedOrigin)) {
          return true;
        }
      }

      return false;
    }

    /**
     * Checks if an origin matches an allowed origin pattern.
     *
     * @param string $origin The origin to check.
     * @param string $allowedOrigin The allowed origin pattern.
     * @return bool Whether the origin matches.
     */
    private function matchesOrigin(string $origin, string $allowedOrigin): bool
    {
      // Exact match
      if ($origin === $allowedOrigin) {
        return true;
      }

      // Wildcard subdomain matching
      if (strpos($allowedOrigin, '*.') !== false) {
        // Extract the domain part after the wildcard
        $domain = substr($allowedOrigin, strpos($allowedOrigin, '*.') + 2);
        
        // Check if the origin ends with the domain
        if (substr($origin, -strlen($domain)) === $domain) {
          // Make sure there's a dot or protocol separator before the domain
          $beforeDomain = substr($origin, 0, -strlen($domain));
          return preg_match('/^https?:\/\/([a-z0-9.-]+\.)?$/', $beforeDomain) === 1;
        }
        
        return false;
      }

      return false;
    }

    /**
     * Gets the current domain from the WordPress site.
     *
     * @return string The current domain URL.
     */
    private function getHomeUrl(): string
    {
      return $this->wpService->getHomeUrl();
    }

    /**
     * Adds wildcard subdomain support to the current domain.
     *
     * @param string $currentDomain The current domain URL.
     * @return string The domain with wildcard subdomain support.
     */
    private function addWildcardToCurrentDomain(string $currentDomain): string
    {
      // Extract domain from URL (e.g., https://example.com -> example.com)
      $parsedUrl = parse_url($currentDomain);
      $domain = $parsedUrl['host'] ?? '';
      
      if (empty($domain)) {
        return $currentDomain;
      }
      
      // Add wildcard subdomain support
      $protocol = $parsedUrl['scheme'] ?? 'https';
      return $protocol . '://*.' . $domain;
    }
}