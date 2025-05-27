<?php

namespace WPMUSecurity;

use WpService\WpService;

class XmlRpc
{
    public function __construct(private WpService $wpService){}

    /**
     * Adds hooks for disabling XML-RPC functionality.
     *
     * @return void
     */
    public function addHooks(): void
    {
      $this->wpService->addFilter('xmlrpc_enabled', [$this, 'disableXmlRpc'], 10, 0);
    }

    /**
     * Disables XML-RPC functionality.
     * This function is used to prevent XML-RPC requests, which can be a vector for attacks.
     *
     * @return bool Always returns false to disable XML-RPC.
     */
    public function disableXmlRpc(): bool
    {
      return false;   
    }
}