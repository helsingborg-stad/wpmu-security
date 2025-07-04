<?php

namespace WPMUSecurity\Admin;

use WpService\WpService;
use AcfService\AcfService;
use WPMUSecurity\HookableInterface;
use AcfExportManager\AcfExportManager;

class Settings implements HookableInterface
{
  private const ACF_DOMAIN_KEY = 'field_68679bef9922a'; // Domain field key
  private const ACF_CATEGORY_KEY = 'field_68679b1075e68'; // Category field key
  private const ACF_OPTION_NAME = 'security_csp_allowed_domains'; // ACF option name for allowed domains

  /**
   * Settings constructor.
   *
   * @param WpService $wpService The WordPress service instance.
   * @param AcfService $acfService The ACF service instance.
   */
  public function __construct(private WpService $wpService, private AcfService $acfService) {}

  /**
   * Adds hooks for the settings functionality.
   *
   * This method registers actions and filters with WordPress to handle
   * the settings page registration, field configuration, CSP domain addition,
   * and domain field sanitization on save.
   *
   * @return void
   */
  public function addHooks(): void
  {
    $this->wpService->addAction('acf/init', [$this, 'registerSettingsPage']);
    $this->wpService->addAction('init', [$this, 'fieldConfigurationHandler']);
    $this->wpService->addFilter('WpSecurity/Csp', [$this, 'addCspDomains'], 10, 1);
    $this->wpService->addFilter('acf/update_value/key=' . self::ACF_DOMAIN_KEY, [$this, 'sanitizeDomainFieldOnSave'], 10, 3);
  }

  /**
   * Registers the settings page with ACF.
   *
   * This method creates an options page in the WordPress admin area
   * where users can manage security settings related to Content Security Policy (CSP).
   *
   * @return void
   */
  public function registerSettingsPage(): void
  {
    //Register a options page with acf
    $this->acfService->addOptionsPage([
      'page_title'  => $this->wpService->__('Security Settings', 'wpmu-security'),
      'menu_title'  => $this->wpService->__('Security', 'wpmu-security'),
      'menu_slug'   => 'wpmu-security-settings',
      'capability'  => 'manage_options',
      'redirect'    => false,
      'parent_slug' => 'options-general.php',
    ]);
  }

  /**
   * This function is used to export and import ACF field groups.
   * It uses the AcfExportManager to handle the export and import process.
   */
  public function fieldConfigurationHandler() {
    $acfExportManager = new AcfExportManager();
    $acfExportManager->setTextdomain('wpmu-security');
    $acfExportManager->setExportFolder(
      realpath(__DIR__ . '/../../..') . '/acf-export',
      'acf-fields'
    );
    $acfExportManager->autoExport([
      'settings' => 'group_686794bedb2eb',
    ]);
    $acfExportManager->import();
  }

  /**
   * This function sanitizes the domain field on save.
   * It ensures that the domain matches a valid pattern and clears it if invalid.
   *
   * @param mixed $value The value of the field being saved.
   * @param int $postId The ID of the post being saved.
   * @param array $field The field array containing field settings.
   * @return mixed The sanitized value.
   */
  public function sanitizeDomainFieldOnSave($value, $postId, $field)
  {
    return preg_replace('/[^a-zA-Z0-9\.\-\*]/', '', trim($value)) ?: '';
  }

  /**
   * This function adds additional domains to the Content Security Policy (CSP) configuration.
   * It retrieves domains from ACF options and categorizes them based on predefined categories.
   *
   * @param array $domains The existing CSP domains categorized by policy.
   * @return array The updated CSP domains with additional domains added.
   */
  public function addCspDomains($domains): array
  {
      $additionalDomains = $this->acfService->getField(self::ACF_OPTION_NAME, 'option', false);

      foreach ($additionalDomains as $domainRecord) {
          $domain   = $domainRecord[self::ACF_DOMAIN_KEY] ?? '';
          $category = $domainRecord[self::ACF_CATEGORY_KEY] ?? '';

          if (empty($domain) || empty($category)) {
              continue;
          }

          if (!isset($domains[$category])) {
              $domains[$category] = [];
          }

          $domains[$category][] = $this->addProtocolToWildcardDomain($domain);
      }

      return $domains;
    }

    /**
     * This function adds the protocol to wildcard domains.
     * If the domain contains a wildcard (e.g., "*.example.com" or "test.*.example.com"),
     *
     * @param string $domain The domain to process.
     * @return string The domain with the protocol added if it was a wildcard domain.
     */
    private function addProtocolToWildcardDomain(string $domain): string
    {
        if (strpos($domain, '*') !== false) {
            return 'https://' . $domain;
        }
        return $domain;
    }
}
