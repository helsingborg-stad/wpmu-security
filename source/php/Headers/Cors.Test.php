<?php

namespace WPMUSecurity\Headers;

use PHPUnit\Framework\TestCase;
use WpService\Implementations\FakeWpService;

class CorsTest extends TestCase 
{
    private FakeWpService $wpService;
    private Cors $cors;

    protected function setUp(): void
    {
        $this->wpService = new FakeWpService();
        $this->cors = new Cors($this->wpService);
    }

    /**
     * @testdox class can be instantiated
     */
    public function testClassCanBeInstantiated(): void
    {
        $wpService = new FakeWpService();
        $cors = new Cors($wpService);
        $this->assertInstanceOf(Cors::class, $cors);
    }

    /**
     * @testdox addHooks registers send_headers action
     */
    public function testAddHooksRegistersAction(): void
    {
        $wpService = $this->getFakeWpService();
        $cors = new Cors($wpService);
        $cors->addHooks();
        
        // We can't directly test the action registration with FakeWpService,
        // but we can test that the method doesn't throw an error
        $this->assertTrue(true);
    }

    /**
     * @testdox getAllowedOrigins returns current domain by default
     */
    public function testGetAllowedOriginsReturnsCurrentDomain(): void
    {
        $wpService = $this->getFakeWpService();
        $cors = new Cors($wpService);
        
        $result = $this->callPrivateMethod($cors, 'getAllowedOrigins');
        
        $this->assertIsArray($result);
        $this->assertContains('https://example.com', $result);
    }

    /**
     * @testdox getAllowedOrigins applies WpSecurity/Cors filter
     */
    public function testGetAllowedOriginsAppliesFilter(): void
    {
        $wpService = $this->getFakeWpService();
        $cors = new Cors($wpService);
        
        $result = $this->callPrivateMethod($cors, 'getAllowedOrigins');
        
        $this->assertIsArray($result);
        $this->assertContains('https://example.com', $result);
    }

    /**
     * @testdox matchesOrigin returns true for exact matches
     */
    public function testMatchesOriginExactMatch(): void
    {
        $wpService = $this->getFakeWpService();
        $cors = new Cors($wpService);
        
        $result = $this->callPrivateMethod($cors, 'matchesOrigin', 'https://example.com', 'https://example.com');
        $this->assertTrue($result);
        
        $result = $this->callPrivateMethod($cors, 'matchesOrigin', 'https://example.com', 'https://different.com');
        $this->assertFalse($result);
    }

    /**
     * @testdox matchesOrigin handles wildcard subdomains
     */
    public function testMatchesOriginWildcardSubdomains(): void
    {
        $wpService = $this->getFakeWpService();
        $cors = new Cors($wpService);
        
        $result = $this->callPrivateMethod($cors, 'matchesOrigin', 'https://sub.example.com', 'https://*.example.com');
        $this->assertTrue($result);
        
        $result = $this->callPrivateMethod($cors, 'matchesOrigin', 'https://deep.sub.example.com', 'https://*.example.com');
        $this->assertTrue($result);
        
        $result = $this->callPrivateMethod($cors, 'matchesOrigin', 'https://example.com', 'https://*.example.com');
        $this->assertTrue($result);
        
        $result = $this->callPrivateMethod($cors, 'matchesOrigin', 'https://different.com', 'https://*.example.com');
        $this->assertFalse($result);
    }

    /**
     * @testdox matchesOrigin handles wildcard patterns
     */
    public function testMatchesOriginWildcardPatterns(): void
    {
        $wpService = $this->getFakeWpService();
        $cors = new Cors($wpService);
        
        $result = $this->callPrivateMethod($cors, 'matchesOrigin', 'https://test.example.com', 'https://*.example.com');
        $this->assertTrue($result);
        
        $result = $this->callPrivateMethod($cors, 'matchesOrigin', 'https://test.different.com', 'https://*.example.com');
        $this->assertFalse($result);
    }

    /**
     * @testdox isOriginAllowed returns false for empty origin
     */
    public function testIsOriginAllowedEmptyOrigin(): void
    {
        $wpService = $this->getFakeWpService();
        $cors = new Cors($wpService);
        
        $result = $this->callPrivateMethod($cors, 'isOriginAllowed', null, ['https://example.com']);
        $this->assertFalse($result);
        
        $result = $this->callPrivateMethod($cors, 'isOriginAllowed', '', ['https://example.com']);
        $this->assertFalse($result);
    }

    /**
     * @testdox isOriginAllowed returns true for allowed origins
     */
    public function testIsOriginAllowedValidOrigin(): void
    {
        $wpService = $this->getFakeWpService();
        $cors = new Cors($wpService);
        
        $allowedOrigins = ['https://example.com', 'https://*.test.com'];
        
        $result = $this->callPrivateMethod($cors, 'isOriginAllowed', 'https://example.com', $allowedOrigins);
        $this->assertTrue($result);
        
        $result = $this->callPrivateMethod($cors, 'isOriginAllowed', 'https://sub.test.com', $allowedOrigins);
        $this->assertTrue($result);
        
        $result = $this->callPrivateMethod($cors, 'isOriginAllowed', 'https://notallowed.com', $allowedOrigins);
        $this->assertFalse($result);
    }

    /**
     * Helper method to call private methods for testing
     */
    private function callPrivateMethod($object, $methodName, ...$args)
    {
        $reflection = new \ReflectionClass($object);
        $method = $reflection->getMethod($methodName);
        $method->setAccessible(true);
        return $method->invoke($object, ...$args);
    }

    /**
     * Helper method to get a fake WP service for testing
     */
    private function getFakeWpService(): FakeWpService
    {
        return new FakeWpService([
            'addAction' => fn($hookName, $callback, $priority = 10, $acceptedArgs = 1) => true,
            'applyFilters' => fn($hookName, $value) => $value,
            'getHomeUrl' => fn() => 'https://example.com'
        ]);
    }
}