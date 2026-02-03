<?php

namespace WPMUSecurity\Setup;

use WpService\WpService;
use WPMUSecurity\HookableInterface;

class PluginActivation implements HookableInterface
{
    public function __construct(private WpService $wpService){}

    /**
     * Adds hooks for plugin activation.
     *
     * @return void
     */
    public function addHooks(): void
    {
        $this->wpService->addAction('wp_loaded', [$this, 'registerActivationHook']);
    }

    /**
     * Registers the activation hook for the plugin.
     *
     * @return void
     */
    public function registerActivationHook(): void
    {
        // Get the main plugin file path
        $pluginFile = $this->wpService->pluginBasename(dirname(__FILE__, 4) . '/wpmu-security.php');
        
        $this->wpService->addAction("activate_{$pluginFile}", [$this, 'onPluginActivation']);
    }

    /**
     * Handles plugin activation tasks.
     *
     * @return void
     */
    public function onPluginActivation(): void
    {
        $this->addHtaccessRules();
    }

    /**
     * Adds CORS-related rules to .htaccess for LiteSpeed cache integration.
     *
     * @return void
     */
    private function addHtaccessRules(): void
    {
        include_once(ABSPATH . 'wp-admin/includes/file.php');
        $htaccessFile = get_home_path() . '.htaccess';

        if (!is_writable($htaccessFile)) {
            $this->wpService->doAction('wpmu_security_htaccess_not_writable', $htaccessFile);
            return;
        }

        $rules = "# Added by WPMU Security Plugin - CORS LiteSpeed Cache Integration\n";
        $rules .= "CacheKeyModify +Header=Origin\n\n";
        $rules .= "Header add Vary \"Origin\"\n";
        $rules .= "# End WPMU Security Plugin\n";

        $existingContent = '';
        if (file_exists($htaccessFile)) {
            $existingContent = file_get_contents($htaccessFile);
        }

        // Check if rules are already present
        if (strpos($existingContent, 'CacheKeyModify +Header=Origin') !== false) {
            return;
        }

        // Add rules to the beginning of the file
        $newContent = $rules . "\n" . $existingContent;
        
        $result = file_put_contents($htaccessFile, $newContent);
        
        if ($result === false) {
            $this->wpService->doAction('wpmu_security_htaccess_write_failed', $htaccessFile);
        } else {
            $this->wpService->doAction('wpmu_security_htaccess_updated', $htaccessFile);
        }
    }
}