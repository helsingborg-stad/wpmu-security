<?php

namespace WPMUSecurity\Component;

use AcfService\Implementations\FakeAcfService;
use PHPUnit\Framework\TestCase;
use WpService\Implementations\FakeWpService;

class FrameTest extends TestCase
{
    private Frame $frame;

    protected function setUp(): void
    {
        $wpService = new FakeWpService([
            'addFilter' => fn($hookName, $callback, $priority = 10, $acceptedArgs = 1) => true,
        ]);

        $acfService = new FakeAcfService([
            'getField' => fn($fieldName, $context, $format) => [
                ['field_69ba7a3ae80fc' => 'www.helsingborg.se'],
                ['field_69ba7a3ae80fc' => 'helsingborg.se'],
            ],
        ]);
        $this->frame = new Frame($wpService, $acfService);
    }

    protected function generateHostList(string $subdomain): array
    {
        return [
            "https://$subdomain/",
            "https://$subdomain",
            "https://$subdomain/path",
            "https://$subdomain/path/",
            "https://$subdomain/path/index.html",
            "https://$subdomain:8080",
            "https://$subdomain:8080/",
            "https://$subdomain:8080/path",
            "https://$subdomain:8080/path/",
            "https://$subdomain:8080/path/index.html",
            "https://www.$subdomain/",
            "https://www.$subdomain",
            "https://www.$subdomain/path",
            "https://www.$subdomain/path/",
            "https://www.$subdomain/path/index.html",
            "https://www.$subdomain:8080",
            "https://www.$subdomain:8080/",
            "https://www.$subdomain:8080/path",
            "https://www.$subdomain:8080/path/",
            "https://www.$subdomain:8080/path/index.html",
        ];
    }

    /**
     * @testdox testWhiteListedHosts() Bypass user acceptance on white-listed hosts
     */
    public function testWhiteListedHosts(): void
    {
        foreach ($this->generateHostList('helsingborg.se') as $host) {
            $result = $this->frame->displayAcceptance($host);
            $this->assertFalse($result, "Host $host should bypass user acceptance");
        }
    }

    /**
     * @testdox testEnforceUserAcceptance() Enforce user acceptance on non-white-listed hosts
     */
    public function testEnforceUserAcceptance(): void
    {
        foreach ($this->generateHostList('dummy.se') as $host) {
            $result = $this->frame->displayAcceptance($host);
            $this->assertTrue($result, "Host $host should require user acceptance");
        }
    }
}
