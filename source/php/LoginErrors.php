<?php

namespace WPMUSecurity;

use WpService\WpService;

class LoginErrors
{
    public function __construct(private WpService $wpService){}

    /**
     * Adds hooks for the password reset functionality.
     *
     * @return void
     */
    public function addHooks()
    {
      $this->wpService->addFilter('login_errors', [$this, 'customLoginErrorMessage']);
    }

    /**
     * Customizes the login error message.
     *
     * @param string $error The original error message.
     * @return string The customized error message.
     */
    public function customLoginErrorMessage($error)
    {
      return $this->wpService->__('Invalid login credentials. Please try again.', 'wpmu-security');
    }
}