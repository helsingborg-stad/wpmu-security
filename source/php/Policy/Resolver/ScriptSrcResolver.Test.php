<?php

namespace WPMUSecurity\Policy\Resolver;

use PHPUnit\Framework\TestCase;
use WPMUSecurity\Policy\Url;
use WPMUSecurity\Policy\DomWrapper;
use DOMDocument;

class ScriptSrcResolverTest extends TestCase
{
    private ScriptSrcResolver $resolver;
    private Url $urlHelper;

    protected function setUp(): void
    {
        $this->urlHelper = new Url();
        $this->resolver = new ScriptSrcResolver($this->urlHelper);
    }

    /**
     * @testdox resolve() extracts domains with ports from script sources
     */
    public function testResolveExtractsDomainsWithPorts(): void
    {
        $html = '
            <html>
                <head>
                    <script src="https://cdn.example.com:8080/script.js"></script>
                    <script src="http://localhost:3000/app.js"></script>
                    <script src="https://api.domain.com:8443/api.js"></script>
                </head>
                <body>
                    <script>
                        // Inline script with URL
                        fetch("https://api.service.com:9000/data");
                    </script>
                </body>
            </html>
        ';

        $dom = new DOMDocument();
        @$dom->loadHTML($html);
        $domWrapper = new DomWrapper($dom);
        $result = $this->resolver->resolve($domWrapper);

        // Should include 'unsafe-eval' and 'unsafe-inline'
        $this->assertContains("'unsafe-eval'", $result);
        $this->assertContains("'unsafe-inline'", $result);

        // Should extract domains with ports
        $this->assertContains('cdn.example.com:8080', $result);
        $this->assertContains('localhost:3000', $result);
        $this->assertContains('api.domain.com:8443', $result);
        $this->assertContains('api.service.com:9000', $result);
    }

    /**
     * @testdox resolve() handles mixed ports and non-ports
     */
    public function testResolveHandlesMixedPortsAndNonPorts(): void
    {
        $html = '
            <html>
                <head>
                    <script src="https://cdn.example.com/script.js"></script>
                    <script src="http://localhost:3000/app.js"></script>
                    <script src="https://api.domain.com/api.js"></script>
                </head>
            </html>
        ';

        $dom = new DOMDocument();
        @$dom->loadHTML($html);
        $domWrapper = new DomWrapper($dom);
        $result = $this->resolver->resolve($domWrapper);

        // Should include 'unsafe-eval'
        $this->assertContains("'unsafe-eval'", $result);

        // Should extract domains correctly
        $this->assertContains('cdn.example.com', $result);
        $this->assertContains('localhost:3000', $result);
        $this->assertContains('api.domain.com', $result);
    }

    /**
     * @testdox resolve() removes duplicates
     */
    public function testResolveRemovesDuplicates(): void
    {
        $html = '
            <html>
                <head>
                    <script src="https://cdn.example.com:8080/script1.js"></script>
                    <script src="https://cdn.example.com:8080/script2.js"></script>
                    <script src="http://localhost:3000/app1.js"></script>
                    <script src="http://localhost:3000/app2.js"></script>
                </head>
            </html>
        ';

        $dom = new DOMDocument();
        @$dom->loadHTML($html);
        $domWrapper = new DomWrapper($dom);
        $result = $this->resolver->resolve($domWrapper);

        // Count occurrences of each domain
        $domainCounts = array_count_values($result);
        
        $this->assertEquals(1, $domainCounts['cdn.example.com:8080'] ?? 0);
        $this->assertEquals(1, $domainCounts['localhost:3000'] ?? 0);
    }
}