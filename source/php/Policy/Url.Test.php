<?php

namespace WPMUSecurity\Policy;

use PHPUnit\Framework\TestCase;

class UrlTest extends TestCase
{
    private Url $url;

    protected function setUp(): void
    {
        $this->url = new Url();
    }

    /**
     * @testdox normalize() preserves port numbers in URLs
     */
    public function testNormalizePreservesPortNumbers(): void
    {
        $testCases = [
            'https://example.com:8080/path' => 'https://example.com:8080/path',
            'http://localhost:3000' => 'http://localhost:3000',
            'https://domain.com:8443/test/' => 'https://domain.com:8443/test',
            'http://127.0.0.1:8080' => 'http://127.0.0.1:8080',
        ];

        foreach ($testCases as $input => $expected) {
            $result = $this->url->normalize($input);
            $this->assertEquals($expected, $result, "Failed to preserve port in URL: $input");
        }
    }

    /**
     * @testdox normalize() handles URLs without ports correctly
     */
    public function testNormalizeHandlesUrlsWithoutPorts(): void
    {
        $testCases = [
            'https://example.com/path' => 'https://example.com/path',
            'http://localhost' => 'http://localhost',
            'https://domain.com/test/' => 'https://domain.com/test',
        ];

        foreach ($testCases as $input => $expected) {
            $result = $this->url->normalize($input);
            $this->assertEquals($expected, $result, "Failed to handle URL without port: $input");
        }
    }

    /**
     * @testdox normalize() converts protocol-relative URLs with ports
     */
    public function testNormalizeConvertsProtocolRelativeUrlsWithPorts(): void
    {
        $testCases = [
            '//example.com:8080/path' => 'https://example.com:8080/path',
            '//localhost:3000' => 'https://localhost:3000',
        ];

        foreach ($testCases as $input => $expected) {
            $result = $this->url->normalize($input);
            $this->assertEquals($expected, $result, "Failed to convert protocol-relative URL with port: $input");
        }
    }

    /**
     * @testdox normalize() removes trailing slashes
     */
    public function testNormalizeRemovesTrailingSlashes(): void
    {
        $testCases = [
            'https://example.com:8080/' => 'https://example.com:8080',
            'http://localhost:3000/path/' => 'http://localhost:3000/path',
        ];

        foreach ($testCases as $input => $expected) {
            $result = $this->url->normalize($input);
            $this->assertEquals($expected, $result, "Failed to remove trailing slash: $input");
        }
    }

    /**
     * @testdox normalize() handles escaped slashes
     */
    public function testNormalizeHandlesEscapedSlashes(): void
    {
        $testCases = [
            'https:\/\/example.com:8080\/path' => 'https://example.com:8080/path',
            'http:\/\/localhost:3000' => 'http://localhost:3000',
        ];

        foreach ($testCases as $input => $expected) {
            $result = $this->url->normalize($input);
            $this->assertEquals($expected, $result, "Failed to handle escaped slashes: $input");
        }
    }
}