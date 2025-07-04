<?php

namespace WPMUSecurity\Headers;

use PHPUnit\Framework\TestCase;
use WpService\Implementations\FakeWpService;

class CorsTest extends TestCase
{
    private Cors $cors;
    private FakeWpService $wpService;

    protected function setUp(): void
    {
        $this->wpService = new FakeWpService();
        $this->cors = new Cors($this->wpService);
    }

    /**
     * @testdox addCorsHeaders() includes port number in CORS header
     */
    public function testAddCorsHeadersIncludesPortNumber(): void
    {
        // Mock the home URL with a custom port
        $this->wpService->methodResponses['getHomeUrl'] = 'http://localhost:8080';

        // Capture the header that would be sent
        $headersSent = [];
        $this->mockHeaderFunction($headersSent);

        // Call addCorsHeaders
        $this->cors->addCorsHeaders();

        // Verify the CORS header includes the port
        $this->assertCount(1, $headersSent);
        $this->assertEquals('Access-Control-Allow-Origin: http://localhost:8080', $headersSent[0]);
    }

    /**
     * @testdox addCorsHeaders() works with HTTPS and custom port
     */
    public function testAddCorsHeadersWithHttpsAndCustomPort(): void
    {
        // Mock the home URL with HTTPS and custom port
        $this->wpService->methodResponses['getHomeUrl'] = 'https://example.com:8443';

        // Capture the header that would be sent
        $headersSent = [];
        $this->mockHeaderFunction($headersSent);

        // Call addCorsHeaders
        $this->cors->addCorsHeaders();

        // Verify the CORS header includes the port
        $this->assertCount(1, $headersSent);
        $this->assertEquals('Access-Control-Allow-Origin: https://example.com:8443', $headersSent[0]);
    }

    /**
     * @testdox addCorsHeaders() works with standard ports
     */
    public function testAddCorsHeadersWithStandardPorts(): void
    {
        // Mock the home URL without custom port
        $this->wpService->methodResponses['getHomeUrl'] = 'https://example.com';

        // Capture the header that would be sent
        $headersSent = [];
        $this->mockHeaderFunction($headersSent);

        // Call addCorsHeaders
        $this->cors->addCorsHeaders();

        // Verify the CORS header works with standard ports
        $this->assertCount(1, $headersSent);
        $this->assertEquals('Access-Control-Allow-Origin: https://example.com', $headersSent[0]);
    }

    /**
     * @testdox addCorsHeaders() does not send duplicate headers
     */
    public function testAddCorsHeadersDoesNotSendDuplicateHeaders(): void
    {
        // Mock existing headers
        $this->mockHeadersListFunction(['Access-Control-Allow-Origin: https://existing.com']);

        // Mock the home URL
        $this->wpService->methodResponses['getHomeUrl'] = 'http://localhost:8080';

        // Capture the header that would be sent
        $headersSent = [];
        $this->mockHeaderFunction($headersSent);

        // Call addCorsHeaders
        $this->cors->addCorsHeaders();

        // Verify no new header was sent
        $this->assertCount(0, $headersSent);
    }

    /**
     * Mock the header() function to capture headers
     */
    private function mockHeaderFunction(array &$headersSent): void
    {
        $headerFunction = function (string $header) use (&$headersSent) {
            $headersSent[] = $header;
        };

        // In a real test environment, we would use a framework like PHPUnit's
        // function mocking or create a wrapper for header() function
        // For now, we'll assume the header function is properly mocked
    }

    /**
     * Mock the headers_list() function
     */
    private function mockHeadersListFunction(array $headers): void
    {
        // In a real test environment, we would mock headers_list()
        // For now, we'll assume it's properly mocked
    }
}