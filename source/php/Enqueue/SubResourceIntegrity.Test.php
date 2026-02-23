<?php

namespace WPMUSecurity\Enqueue;

use PHPUnit\Framework\TestCase;
use WpService\Implementations\FakeWpService;
use WPMUSecurity\Config;

class SubResourceIntegrityTest extends TestCase
{
    private SubResourceIntegrity $sri;
    private FakeWpService $wpService;
    private Config $config;

    protected function setUp(): void
    {
        $this->wpService = new FakeWpService([
            'addFilter' => fn($hookName, $callback, $priority = 10, $acceptedArgs = 1) => true,
            'applyFilters' => fn($hookName, $value) => $value,
            'getHomeUrl' => 'http://localhost:8080',
            'includesUrl' => 'http://localhost:8080/wp-includes/',
        ]);
        $this->config = new Config('WPSecurity/', $this->wpService);
        $this->sri = new SubResourceIntegrity($this->wpService, $this->config);
    }

    /**
     * @testdox isLocalAsset() correctly identifies local assets with custom ports
     */
    public function testIsLocalAssetHandlesCustomPorts(): void
    {

        // Test URLs with the same port should be considered local
        $localUrls = [
            'http://localhost:8080/wp-content/themes/test/style.css',
            'https://localhost:8080/wp-includes/js/script.js',
            'http://localhost:8080/wp-content/uploads/file.js',
        ];

        foreach ($localUrls as $url) {
            $result = $this->callPrivateMethod($this->sri, 'isLocalAsset', [$url]);
            $this->assertTrue($result, "URL should be considered local: $url");
        }

        // Test URLs with different ports should not be considered local
        $nonLocalUrls = [
            'http://localhost:3000/wp-content/themes/test/style.css',
            'http://localhost/wp-includes/js/script.js', // no port
            'http://localhost:9000/wp-content/uploads/file.js',
        ];

        foreach ($nonLocalUrls as $url) {
            $result = $this->callPrivateMethod($this->sri, 'isLocalAsset', [$url]);
            $this->assertFalse($result, "URL should not be considered local: $url");
        }
    }

    /**
     * @testdox normalizeProtocol() preserves port numbers
     */
    public function testNormalizeProtocolPreservesPortNumbers(): void
    {
        $testCases = [
            'https://example.com:8080/path' => 'example.com:8080/path',
            'http://localhost:3000' => 'localhost:3000',
            'https://domain.com:8443/test/' => 'domain.com:8443/test/',
        ];

        foreach ($testCases as $input => $expected) {
            $result = $this->callPrivateMethod($this->sri, 'normalizeProtocol', [$input]);
            $this->assertEquals($expected, $result, "Failed to preserve port when removing protocol: $input");
        }
    }

    /**
     * @testdox createRelativePath() handles URLs with custom ports
     */
    public function testCreateRelativePathHandlesCustomPorts(): void
    {
        // Mock WordPress constants and functions
        $this->defineConstantsIfNeeded();

        // Test wp-content URL with custom port
        $contentUrl = 'http://localhost:8080/wp-content/themes/test/style.css';
        $expectedPath = '/var/www/html/wp-content/themes/test/style.css';
        
        $result = $this->callPrivateMethod($this->sri, 'createRelativePath', [$contentUrl]);
        $this->assertEquals($expectedPath, $result, "Failed to create relative path for wp-content with custom port");

        // Test wp-includes URL with custom port
        $includesUrl = 'http://localhost:8080/wp-includes/js/script.js';
        $expectedPath = '/var/www/html/wp-includes/js/script.js';
        
        $result = $this->callPrivateMethod($this->sri, 'createRelativePath', [$includesUrl]);
        $this->assertEquals($expectedPath, $result, "Failed to create relative path for wp-includes with custom port");
    }

    /**
     * Define WordPress constants if they don't exist
     */
    private function defineConstantsIfNeeded(string $contentUrl = 'http://localhost:8080/wp-content', string $siteUrl = 'http://localhost:8080'): void
    {
        if (!defined('WP_CONTENT_URL')) {
            define('WP_CONTENT_URL', $contentUrl);
        }
        if (!defined('WP_CONTENT_DIR')) {
            define('WP_CONTENT_DIR', '/var/www/html/wp-content');
        }
        if (!defined('ABSPATH')) {
            define('ABSPATH', '/var/www/html/');
        }
        if (!defined('WPINC')) {
            define('WPINC', 'wp-includes');
        }
    }

    /**
     * Helper method to call private methods for testing
     */
    private function callPrivateMethod(object $object, string $methodName, array $parameters = [])
    {
        $reflection = new \ReflectionClass($object);
        $method = $reflection->getMethod($methodName);
        $method->setAccessible(true);
        return $method->invokeArgs($object, $parameters);
    }
}