<?php

/*
Plugin Name:    WPMU Security
Description:    Adds basic security features to WordPress.
Version:        1.0.0
Author:         Sebastian Thulin
*/

namespace WPMUSecurity;

use WpService\Implementations\NativeWpService;

if (! defined('WPINC')) {
    die;
}

class WPMUSecurity
{
  public function __construct()
  {
    $this->autoload();

    $wpService = new NativeWpService();

    $this->setupGenericLoginErrors($wpService);
    $this->setupGenericPasswordReset($wpService);
  }

  /**
   * Feature: Generic Login Errors
   * This feature replaces the default WordPress login error messages with a generic message. 
   * This prevents attackers from gaining information about valid usernames or email addresses.
   *
   * @return void
   */
  private function setupGenericLoginErrors($wpService)
  {
    $loginErrors = new \WPMUSecurity\LoginErrors($wpService);
    $loginErrors->addHooks();
  }

  /**
   * Feature: Password Reset
   * This feature replaces the default WordPress password reset functionality with a generic message.
   * This prevents attackers from gaining information about valid usernames or email addresses during the password reset process.
   *
   * @return void
   */
  private function setupGenericPasswordReset($wpService)
  {
    $passwordReset = new \WPMUSecurity\PasswordReset($wpService);
    $passwordReset->addHooks();
  }

  /**
   * Autoloads the required classes.
   *
   * @return void
   */
  private function autoload()
  {
    if (file_exists(__DIR__ . '/vendor/autoload.php')) {
      require __DIR__ . '/vendor/autoload.php';
    } else {
      throw new \Exception('Autoload file not found. Please run `composer install` to generate it.');
    }
  }
}

new \WPMUSecurity\WPMUSecurity();
