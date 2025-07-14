<?php

namespace WPMUSecurity\Admin;

use PHPUnit\Framework\TestCase;
use WpService\Implementations\FakeWpService;
use AcfService\Implementations\FakeAcfService;

class SettingsTest extends TestCase 
{
    private FakeWpService $wpService;
    private FakeAcfService $acfService;
    private Settings $settings;

    protected function setUp(): void
    {
        $this->wpService = new FakeWpService([
            'addAction' => fn($hook, $callback) => true,
            'addFilter' => fn($hook, $callback) => true,
            '__' => fn($text) => $text,
            'pluginBasename' => fn($path) => $path,
            'loadPluginTextdomain' => fn() => true
        ]);

        $this->acfService = new FakeAcfService([
            'addOptionsPage' => fn($args) => true,
            'getField' => function($field, $location) {
                if ($field === 'security_cors_allowed_domains') {
                    return [
                        ['domain' => 'example.com'],
                        ['domain' => 'test.com']
                    ];
                }
                if ($field === 'security_cors_subdomain_support') {
                    return true;
                }
                return false;
            }
        ]);

        $this->settings = new Settings($this->wpService, $this->acfService);
    }

    /**
     * @testdox addCorsOrigins adds custom origins from ACF settings
     */
    public function testAddCorsOriginsFromAcfSettings(): void
    {
        $initialOrigins = ['https://mysite.com'];
        $result = $this->settings->addCorsOrigins($initialOrigins);
        
        $this->assertIsArray($result);
        $this->assertContains('https://mysite.com', $result);
        $this->assertContains('https://*.example.com', $result);
        $this->assertContains('https://*.test.com', $result);
    }

    /**
     * @testdox addCorsOrigins handles empty ACF settings gracefully
     */
    public function testAddCorsOriginsEmptySettings(): void
    {
        // Override ACF service to return empty settings
        $this->acfService = new FakeAcfService([
            'getField' => fn($field, $location) => null
        ]);
        
        $this->settings = new Settings($this->wpService, $this->acfService);
        
        $initialOrigins = ['https://mysite.com'];
        $result = $this->settings->addCorsOrigins($initialOrigins);
        
        $this->assertEquals($initialOrigins, $result);
    }

    /**
     * @testdox formatDomainForCors handles subdomain support correctly
     */
    public function testFormatDomainForCorsSubdomainSupport(): void
    {
        $reflection = new \ReflectionClass($this->settings);
        $method = $reflection->getMethod('formatDomainForCors');
        $method->setAccessible(true);
        
        // Test with subdomain support enabled
        $result = $method->invoke($this->settings, 'example.com', true);
        $this->assertEquals('https://*.example.com', $result);
        
        // Test with subdomain support disabled
        $result = $method->invoke($this->settings, 'example.com', false);
        $this->assertEquals('https://example.com', $result);
        
        // Test with existing wildcard
        $result = $method->invoke($this->settings, '*.example.com', true);
        $this->assertEquals('https://*.example.com', $result);
    }

    /**
     * @testdox formatDomainForCors adds protocol when missing
     */
    public function testFormatDomainForCorsProtocol(): void
    {
        $reflection = new \ReflectionClass($this->settings);
        $method = $reflection->getMethod('formatDomainForCors');
        $method->setAccessible(true);
        
        $result = $method->invoke($this->settings, 'example.com', false);
        $this->assertEquals('https://example.com', $result);
        
        $result = $method->invoke($this->settings, 'http://example.com', false);
        $this->assertEquals('http://example.com', $result);
    }
}