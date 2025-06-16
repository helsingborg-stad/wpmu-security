<?php

namespace WPMUSecurity\Headers;

use WpService\WpService;

class Permissions
{
    public function __construct(private WpService $wpService){}

    /**
     * Adds hooks for the password reset functionality.
     *
     * @return void
     */
    public function addHooks(): void
    {
      $this->wpService->addAction('send_headers', [$this, 'addPermissionsPolicy']);
    }

    /**
     * Adds Permissions Policy headers to the response.
     * This controls which features can be used in the browser.
     * It checks if the Permissions Policy header is already set to avoid duplicates.
     * If not set, it adds a default Permissions Policy header.
     */
    public function addPermissionsPolicy(): void
    {
      foreach (headers_list() as $header) {
        if (stripos($header, 'Permissions-Policy:') === 0) {
          return;
        }
      }
      if (!headers_sent()) {
        header('Permissions-Policy: autoplay=(self), fullscreen=(self), microphone=(), camera=(), geolocation=(), payment=();');
      }      
    }
}