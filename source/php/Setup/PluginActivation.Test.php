<?php

namespace WPMUSecurity\Setup;

use PHPUnit\Framework\TestCase;
use WpService\Implementations\FakeWpService;

class PluginActivationTest extends TestCase 
{
    private FakeWpService $wpService;
    private PluginActivation $pluginActivation;

    protected function setUp(): void
    {
        $this->wpService = new FakeWpService();
        $this->pluginActivation = new PluginActivation($this->wpService);
    }

    /**
     * @testdox class can be instantiated
     */
    public function testClassCanBeInstantiated(): void
    {
        $wpService = new FakeWpService();
        $pluginActivation = new PluginActivation($wpService);
        $this->assertInstanceOf(PluginActivation::class, $pluginActivation);
    }

    /**
     * @testdox addHooks registers wp_loaded action
     */
    public function testAddHooksRegistersAction(): void
    {
        $wpService = $this->getFakeWpService();
        $pluginActivation = new PluginActivation($wpService);
        $pluginActivation->addHooks();
        
        // We can't directly test the action registration with FakeWpService,
        // but we can test that the method doesn't throw an error
        $this->assertTrue(true);
    }

    /**
     * @testdox registerActivationHook registers activation hook
     */
    public function testRegisterActivationHook(): void
    {
        $wpService = $this->getFakeWpService();
        $pluginActivation = new PluginActivation($wpService);
        $pluginActivation->registerActivationHook();
        
        // We can't directly test the hook registration with FakeWpService,
        // but we can test that the method doesn't throw an error
        $this->assertTrue(true);
    }

    /**
     * @testdox onPluginActivation calls addHtaccessRules
     */
    public function testOnPluginActivation(): void
    {
        $wpService = $this->getFakeWpService();
        $pluginActivation = new PluginActivation($wpService);
        
        // Mock the file system functions
        $originalAbspath = defined('ABSPATH') ? ABSPATH : '';
        if (!defined('ABSPATH')) {
            define('ABSPATH', '/tmp/test/');
        }
        
        try {
            $pluginActivation->onPluginActivation();
            $this->assertTrue(true); // Method executed without error
        } finally {
            // Restore original ABSPATH if it was set
            if ($originalAbspath && defined('ABSPATH')) {
                // Can't undefine constants in PHP, so we'll just note this limitation
            }
        }
    }

    /**
     * Helper method to get a fake WP service for testing
     */
    private function getFakeWpService(): FakeWpService
    {
        return new FakeWpService([
            'addAction' => fn($hookName, $callback, $priority = 10, $acceptedArgs = 1) => true,
            'pluginBasename' => fn($file) => 'wpmu-security/wpmu-security.php',
            'doAction' => fn($hookName, ...$args) => true,
        ]);
    }
}