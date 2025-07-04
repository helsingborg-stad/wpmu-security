<?php

namespace WPMUSecurity\Policy;

use PHPUnit\Framework\TestCase;
use WpService\Implementations\FakeWpService;

class ContentSecurityPolicyPortTest extends TestCase
{
    private ContentSecurityPolicy $csp;
    private FakeWpService $wpService;

    protected function setUp(): void
    {
        $this->wpService = new FakeWpService();
        $this->csp = new ContentSecurityPolicy($this->wpService);
    }

    /**
     * @testdox getCategorizedDomainsFromMarkup() extracts domains with ports
     */
    public function testGetCategorizedDomainsFromMarkupExtractsDomainsWithPorts(): void
    {
        $html = '
            <html>
                <head>
                    <script src="https://cdn.example.com:8080/script.js"></script>
                    <link rel="stylesheet" href="http://localhost:3000/style.css">
                    <script>
                        // Inline script with API call
                        fetch("https://api.service.com:9000/data");
                    </script>
                </head>
                <body>
                    <img src="https://images.domain.com:8443/image.png" alt="test">
                    <iframe src="http://embed.site.com:8080/widget"></iframe>
                </body>
            </html>
        ';

        $result = $this->csp->getCategorizedDomainsFromMarkup($html);

        // Check script-src includes domains with ports
        $this->assertArrayHasKey('script-src', $result);
        $this->assertContains('cdn.example.com:8080', $result['script-src']);
        $this->assertContains('api.service.com:9000', $result['script-src']);

        // Check style-src includes domains with ports
        $this->assertArrayHasKey('style-src', $result);
        $this->assertContains('localhost:3000', $result['style-src']);

        // Check img-src includes domains with ports
        $this->assertArrayHasKey('img-src', $result);
        $this->assertContains('images.domain.com:8443', $result['img-src']);

        // Check frame-src includes domains with ports
        $this->assertArrayHasKey('frame-src', $result);
        $this->assertContains('embed.site.com:8080', $result['frame-src']);
    }

    /**
     * @testdox getCategorizedDomainsFromMarkup() handles mixed port and non-port scenarios
     */
    public function testGetCategorizedDomainsFromMarkupHandlesMixedPortScenarios(): void
    {
        $html = '
            <html>
                <head>
                    <script src="https://cdn.example.com/script.js"></script>
                    <script src="http://localhost:3000/app.js"></script>
                    <link rel="stylesheet" href="https://styles.domain.com:8443/main.css">
                    <link rel="stylesheet" href="http://fonts.googleapis.com/css">
                </head>
                <body>
                    <img src="https://images.domain.com/image.png" alt="test">
                    <img src="http://localhost:8080/uploads/photo.jpg" alt="local">
                </body>
            </html>
        ';

        $result = $this->csp->getCategorizedDomainsFromMarkup($html);

        // Check script-src includes both port and non-port domains
        $this->assertArrayHasKey('script-src', $result);
        $this->assertContains('cdn.example.com', $result['script-src']);
        $this->assertContains('localhost:3000', $result['script-src']);

        // Check style-src includes both port and non-port domains
        $this->assertArrayHasKey('style-src', $result);
        $this->assertContains('styles.domain.com:8443', $result['style-src']);
        $this->assertContains('fonts.googleapis.com', $result['style-src']);

        // Check img-src includes both port and non-port domains
        $this->assertArrayHasKey('img-src', $result);
        $this->assertContains('images.domain.com', $result['img-src']);
        $this->assertContains('localhost:8080', $result['img-src']);
    }

    /**
     * @testdox createCategorizedCspHeader() includes ports in CSP header
     */
    public function testCreateCategorizedCspHeaderIncludesPortsInCspHeader(): void
    {
        $cspPolicies = [
            'script-src' => ["'unsafe-eval'", "'unsafe-inline'", 'cdn.example.com:8080', 'api.service.com:9000'],
            'style-src' => ["'unsafe-inline'", 'styles.domain.com:8443', 'fonts.googleapis.com'],
            'img-src' => ['images.domain.com:8443', 'localhost:8080', 'data:'],
            'frame-src' => ['embed.site.com:8080', "'self'"],
        ];

        $result = $this->csp->createCategorizedCspHeader($cspPolicies);

        // Verify the header includes domains with ports
        $this->assertStringContainsString('cdn.example.com:8080', $result);
        $this->assertStringContainsString('api.service.com:9000', $result);
        $this->assertStringContainsString('styles.domain.com:8443', $result);
        $this->assertStringContainsString('images.domain.com:8443', $result);
        $this->assertStringContainsString('localhost:8080', $result);
        $this->assertStringContainsString('embed.site.com:8080', $result);

        // Verify the header structure is correct
        $this->assertStringContainsString('script-src', $result);
        $this->assertStringContainsString('style-src', $result);
        $this->assertStringContainsString('img-src', $result);
        $this->assertStringContainsString('frame-src', $result);
    }

    /**
     * @testdox Full integration test with port handling
     */
    public function testFullIntegrationWithPortHandling(): void
    {
        // Create HTML with various elements using custom ports
        $html = '
            <!DOCTYPE html>
            <html>
                <head>
                    <script src="https://cdn.example.com:8080/jquery.js"></script>
                    <link rel="stylesheet" href="http://localhost:3000/bootstrap.css">
                    <script>
                        // API calls with ports
                        fetch("https://api.service.com:9000/users");
                        XMLHttpRequest.open("GET", "http://analytics.site.com:8443/track");
                    </script>
                </head>
                <body>
                    <img src="https://images.cdn.com:8080/logo.png" alt="logo">
                    <iframe src="http://widgets.example.com:3000/chat"></iframe>
                    <form action="https://forms.service.com:8443/submit">
                        <input type="text" name="email">
                        <button type="submit">Submit</button>
                    </form>
                </body>
            </html>
        ';

        // Extract domains
        $domains = $this->csp->getCategorizedDomainsFromMarkup($html);
        
        // Generate CSP header
        $header = $this->csp->createCategorizedCspHeader($domains);

        // Verify all expected domains with ports are included
        $expectedDomains = [
            'cdn.example.com:8080',
            'localhost:3000',
            'api.service.com:9000',
            'analytics.site.com:8443',
            'images.cdn.com:8080',
            'widgets.example.com:3000',
            'forms.service.com:8443'
        ];

        foreach ($expectedDomains as $domain) {
            $this->assertStringContainsString($domain, $header, "CSP header should contain domain: $domain");
        }

        // Verify CSP structure
        $this->assertStringContainsString('script-src', $header);
        $this->assertStringContainsString('style-src', $header);
        $this->assertStringContainsString('img-src', $header);
        $this->assertStringContainsString('frame-src', $header);
        $this->assertStringContainsString('form-action', $header);
        $this->assertStringContainsString('connect-src', $header);
    }
}