<?php

/*
 * Plugin Name:    WPMU Security
 * Description:    Adds basic security features to WordPress.
 * Version: 0.5.8
 * Author:         Sebastian Thulin
 * Author URI:     https://github.com/helsingborg-stad
 * License:        MIT
 * License URI:    https://opensource.org/licenses/MIT
 * Text Domain:    wpmu-security
 * Domain Path:    /languages
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
    //Autoload
    $this->autoload();
    
    //Services
    $wpService = new NativeWpService();
    $config = new \WPMUSecurity\Config($wpService);

    //Translations
    $this->loadTranslations($wpService);

    //Features
    $this->setupGenericLoginErrors($wpService);
    $this->setupGenericPasswordReset($wpService);
    $this->setupHsts($wpService, $config);
    $this->setupCors($wpService, $config);
    $this->setupSubResourceIntegrity($wpService, $config);
    $this->setupXmlRpc($wpService);
    $this->setupContentSecurityPolicy($wpService, $config);
  }

  /**
   * Feature: Content Security Policy (CSP)
   * This feature adds a Content Security Policy header to the response, which helps prevent XSS attacks
   * by controlling which resources can be loaded on the page. It checks if the CSP header is already set
   * to avoid duplicates.
   *
   * @return void
   */
  public function setupContentSecurityPolicy($wpService, $config)
  {
    $csp = new \WPMUSecurity\Policy\ContentSecurityPolicy($wpService, $config);
    $csp->addHooks();
  }

  /**
   * Feature: XML-RPC
   * This feature disables XML-RPC functionality to prevent potential attacks.
   * It checks if the XML-RPC functionality is already disabled to avoid duplicates.
   *
   * @return void
   */
  public function setupXmlRpc($wpService)
  {
    $xmlRpc = new \WPMUSecurity\XmlRpc($wpService);
    $xmlRpc->addHooks();
  }

  /**
   * Feature: Subresource Integrity (SRI)
   * This feature adds SRI attributes to script and link tags, ensuring that the resources loaded
   * have not been tampered with. It checks if the SRI attributes are already set to avoid duplicates.
   *
   * @return void
   */
  public function setupSubResourceIntegrity($wpService, $config)
  {
    $sri = new \WPMUSecurity\Enqueue\SubResourceIntegrity($wpService, $config);
    $sri->addHooks();
  }

  /**
   * Feature: CORS
   * This feature adds CORS headers to the response, allowing cross-origin requests from the current domain.
   * It checks if the headers are already set to avoid duplicates.
   *
   * @return void
   */
  public function setupCors($wpService, $config)
  {
    $cors = new \WPMUSecurity\Headers\Cors($wpService);
    $cors->addHooks();
  }

  /**
   * Feature: HSTS (HTTP Strict Transport Security)
   * This feature adds the HSTS header to the response, enforcing HTTPS connections for the specified max age.
   * It checks if the current domain configuration is SSL before adding the header.
   *
   * @return void
   */
  public function setupHsts($wpService, $config)
  {
    $hsts = new \WPMUSecurity\Headers\Hsts($wpService, $config);
    $hsts->addHooks();
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
    $loginErrors = new \WPMUSecurity\Authentication\LoginErrors($wpService);
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
    $passwordReset = new \WPMUSecurity\Authentication\PasswordReset($wpService);
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

  private function loadTranslations($wpService)
  {
    $wpService->addAction('init', function () use ($wpService) {
      $wpService->loadPluginTextdomain(
        'wpmu-security', 
        false, 
        $wpService->pluginBasename(dirname(__FILE__)) . '/languages'
      );
    });
  }
}

new \WPMUSecurity\WPMUSecurity();
