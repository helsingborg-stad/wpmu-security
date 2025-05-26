<?php

namespace WPMUSecurity\Headers;

use WpService\WpService;
use WPMUSecurity\Config;

class Hsts
{
    public function __construct(private WpService $wpService, private Config $config){}

    /**
     * Adds hooks for the password reset functionality.
     *
     * @return void
     */
    public function addHooks()
    {
      $this->wpService->addAction('send_headers', [$this, 'addHstsHeader']);
    }

    /**
     * Adds the HSTS header to the response.
     * This header enforces HTTPS connections for the specified max age.
     */
    public function addHstsHeader(): void
    {
      if(!$this->hasSsl()) {
        return;
      }

      header("Strict-Transport-Security: max-age=" . $this->config->getHstsMaxAge() . ";");
    }

    /**
     * Checks if the current donain configuration is ssl.
     */
    private function hasSsl()
    {
      $domain = $this->wpService->getSiteUrl();
      return strpos($domain, 'https://') === 0 || strpos($domain, 'http://') === 0;
    }
}