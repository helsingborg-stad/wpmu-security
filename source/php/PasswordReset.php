<?php

namespace WPMUSecurity;

use WpService\WpService;
use WP_Error;

class PasswordReset
{
    public function __construct(private WpService $wpService){}

    /**
     * Adds hooks for the password reset functionality.
     *
     * @return void
     */
    public function addHooks()
    {
      $this->wpService->addFilter('user_password_reset_errors', [$this, 'customPasswordResetErrors'], 10, 1);
    }

    /**
     * Customizes the password reset error messages.
     *
     * @param WP_Error $errors The original error object.
     * @param array $userData The user data array.
     * @return WP_Error The modified error object.
     */
    public function customPasswordResetErrors($errors)
    {
      if ($errors->get_error_code()) {
        $errors = new WP_Error(
          'invalid_combination', 
          $this->wpService->__('If the information provided is correct, you will receive a reset email shortly.', 'wpmu-security')
        ); 
      }
      return $errors;
    }
}