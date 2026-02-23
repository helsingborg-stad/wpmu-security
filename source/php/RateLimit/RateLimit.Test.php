<?php

namespace WPMUSecurity\RateLimit;

use PHPUnit\Framework\TestCase;
use WpService\Implementations\FakeWpService;
use WPMUSecurity\Config;

class RateLimitTest extends TestCase
{
    private RateLimit $rateLimit;
    private FakeWpService $wpService;
    private Config $config;

    protected function setUp(): void
    {
        // Simulate persistent object cache with expiration
        static $cache = [];

        $this->wpService = new FakeWpService([
            'wpCacheGet' => function($key, $group) use (&$cache) {
                $now = time();
                if (isset($cache[$group][$key])) {
                    $entry = $cache[$group][$key];
                    if ($entry['expires'] === 0 || $entry['expires'] > $now) {
                        return $entry['data'];
                    } else {
                        unset($cache[$group][$key]);
                        return false;
                    }
                }
                return false;
            },
            'wpCacheSet' => function($key, $data, $group, $expire) use (&$cache) {
                $cache[$group][$key] = [
                    'data' => $data,
                    'expires' => $expire > 0 ? (time() + $expire) : 0
                ];
                return true;
            },
            '__' => fn($text, $domain) => $text,
            'doAction' => fn($hook, $args = []) => null,
            'sanitizeTextField' => fn($text) => $text,
        ]);

        $this->config     = new Config('WPSecurity/', $this->wpService);
        $this->rateLimit  = new RateLimit($this->wpService, $this->config);

        //Mock server variables
        $_SERVER['REMOTE_ADDR']     = '127.0.0.1';
        $_SERVER['HTTP_USER_AGENT'] = 'phpunit';
    }

    /**
     * @testdox init() allows requests within limit
     */
    public function testAllowsRequestsWithinLimit(): void
    {
        $error = $this->rateLimit->init(3, 60, 'test_action');
        $this->assertNull($error, 'Should allow request within limit');
    }

    /**
     * @testdox init() blocks requests over limit
     */
    public function testBlocksRequestsOverLimit(): void
    {
        // Simulate 3 requests to reach the limit
        $this->rateLimit->init(3, 60, 'test_action');
        $this->rateLimit->init(3, 60, 'test_action');
        $this->rateLimit->init(3, 60, 'test_action');

        // 4th request should be blocked
        $error = $this->rateLimit->init(3, 60, 'test_action');

        $this->assertNotNull($error, 'Should block request over limit');
        $this->assertInstanceOf(\WP_Error::class, $error, 'Should return WP_Error on block');
    }

    /**
     * @testdox init() resets count after time window
     */
    public function testResetsAfterTimeWindow(): void
    {
        $this->rateLimit->init(2, 1, 'reset_action');
        $this->rateLimit->init(2, 1, 'reset_action');
        // Simulate time passing
        sleep(2);
        $error = $this->rateLimit->init(2, 1, 'reset_action');
        $this->assertNull($error, 'Should reset after time window');
    }

    /**
     * @testdox init() uses unique identifier per user
     */
    public function testUniqueIdentifierPerUser(): void
    {
        $_SERVER['REMOTE_ADDR'] = '192.168.1.1';
        $_SERVER['HTTP_USER_AGENT'] = 'userA';
        $errorA = $this->rateLimit->init(1, 60, 'unique_action');
        $_SERVER['REMOTE_ADDR'] = '192.168.1.2';
        $_SERVER['HTTP_USER_AGENT'] = 'userB';
        $errorB = $this->rateLimit->init(1, 60, 'unique_action');
        $this->assertNull($errorA);
        $this->assertNull($errorB);
    }

}