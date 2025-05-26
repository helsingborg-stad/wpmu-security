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
     * This allows cross-origin requests from the current domain and nothing else.
     * It checks if the headers are already set to avoid duplicates.
     * If not set, it adds the Access-Control-Allow-Origin header with the current domain.
     */
    public function addCorsHeaders(): void
    {
      foreach (headers_list() as $header) {
        if (stripos($header, 'Access-Control-Allow-Origin:') === 0) {
          return;
        }
      }
      if (!headers_sent()) {
        header('Access-Control-Allow-Origin: ' . $this->getHomeUrl());
      }      
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
}