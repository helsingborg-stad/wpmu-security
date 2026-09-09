<?php

namespace WPMUSecurity\Enqueue;

use PHPUnit\Framework\TestCase;
use WpService\Implementations\FakeWpService;
use WPMUSecurity\Config;

class VersionTest extends TestCase
{
    private Version $version;

    protected function setUp(): void
    {
        $wpService = new FakeWpService([
            'addFilter' => static fn() => true,
            'applyFilters' => static fn($hookName, $value) => $hookName === 'WPSecurity/GetAssetVersionObfuscationSalt'
                ? 'test-salt'
                : $value,
            'getBloginfo' => '6.8.1',
        ]);

        $this->version = new Version($wpService, new Config('WPSecurity/', $wpService));
    }

    /**
     * @testdox obfuscateVersion() replaces the current WordPress version
     */
    public function testObfuscateVersionReplacesCurrentWordPressVersion(): void
    {
        $expectedHash = hash_hmac('sha256', '6.8.1', 'test-salt');

        $result = $this->version->obfuscateVersion('https://example.test/wp-includes/js/wp-embed.min.js?ver=6.8.1');

        static::assertSame(
            'https://example.test/wp-includes/js/wp-embed.min.js?ver=' . $expectedHash,
            $result
        );
    }

    /**
     * @testdox obfuscateVersion() preserves URLs with another version value
     */
    public function testObfuscateVersionPreservesOtherVersionValues(): void
    {
        $source = 'https://example.test/wp-content/themes/example/app.js?ver=1.2.3';

        $result = $this->version->obfuscateVersion($source);

        static::assertSame($source, $result);
    }

    /**
     * @testdox obfuscateVersion() preserves the URL when no salt is configured
     */
    public function testObfuscateVersionPreservesUrlWhenSaltIsEmpty(): void
    {
        $wpService = new FakeWpService([
            'applyFilters' => static fn($hookName, $value) => '',
            'getBloginfo' => '6.8.1',
        ]);
        $version = new Version($wpService, new Config('WPSecurity/', $wpService));
        $source = 'https://example.test/wp-includes/js/wp-embed.min.js?ver=6.8.1';

        $result = $version->obfuscateVersion($source);

        static::assertSame($source, $result);
    }
}