<?php

namespace WPMUSecurity\RateLimit;

use WPMUSecurity\Config;
use WpService\WpService;

/**
 * Rate limit validator to prevent abuse and DoS attacks
 * 
 * This class implements rate limiting using WordPress object cache
 * to track and limit the number of form submissions per identifier
 * (typically IP address + user agent) within a time window.
 * 
 * This should be applied as the last validator to ensure rate limiting
 * only occurs after all other validations have passed.
 * 
 * Note: Requires a persistent object cache (e.g., Redis, Memcached) to be 
 * configured in WordPress for proper rate limiting across requests.
 */
class RateLimit
{
    public function __construct(
        private WpService $wpService,
        private Config $config
    ) {
    }

    /**
     * @inheritDoc
     */
    public function validate(array $data, WP_REST_Request $request)
    {
        $identifier = $this->getRateLimitIdentifier();
        $action = 'submit_form';
        
        if ($this->isRateLimited($identifier, $action)) {
            new WP_Error(
              'rate_limit_exceeded',
              $this->wpService->__('Too many requests. Please try again later.', 'wpmu-security'),
              ['status' => 429]
            );
        }
        
    }

    /**
     * Check if the identifier has exceeded the rate limit
     *
     * @param string $identifier Unique identifier (typically IP + user agent hash)
     * @param string $action Action being rate limited
     * @return bool True if rate limited (exceeded), false if within limits
     */
    private function isRateLimited(string $identifier, string $action): bool
    {
        $config = $this->config->getRateLimitSettings();
        $cacheKey = $this->getCacheKey($identifier, $action);
        $cacheData = $this->initializeCacheData($cacheKey, $config);
        $cacheData = $this->resetCacheIfExpired($cacheData, $config);

        if ($this->hasExceededLimit($cacheData, $config, $identifier, $action)) {
            return true;
        }

        // Increment counter and store in cache
        $cacheData['count']++;
        $this->wpService->wpCacheSet(
            $cacheKey,
            $cacheData,
            $config['cache_group'],
            $config['time_window']
        );

        return false;
    }

    /**
     * Initialize cache data if not present
     */
    private function initializeCacheData(string $cacheKey, array $config): array
    {
        $cacheData = $this->wpService->wpCacheGet($cacheKey, $config['cache_group']);
        if ($cacheData === false) {
            $cacheData = [
                'count' => 0,
                'expires' => time() + $config['time_window']
            ];
        }
        return $cacheData;
    }

    /**
     * Reset cache data if expired
     */
    private function resetCacheIfExpired(array $cacheData, array $config): array
    {
        if ($cacheData['expires'] <= time()) {
            $cacheData = [
                'count' => 0,
                'expires' => time() + $config['time_window']
            ];
        }
        return $cacheData;
    }

    /**
     * Check if submission limit is exceeded and log if so
     */
    private function hasExceededLimit(array $cacheData, array $config, string $identifier, string $action): bool
    {
        if ($cacheData['count'] >= $config['submission_limit']) {
            // Log rate limit event for monitoring
            $this->wpService->doAction('modularity_frontend_form_rate_limit_exceeded', [
                'identifier' => $identifier,
                'action' => $action,
                'count' => $cacheData['count'],
                'limit' => $config['submission_limit']
            ]);
            return true;
        }
        return false;
    }

    /**
     * Generate a cache key for rate limiting
     *
     * @param string $identifier Unique identifier
     * @param string $action Action being rate limited
     * @return string Cache key
     */
    private function getCacheKey(string $identifier, string $action): string
    {
        return md5($identifier . $action);
    }

    /**
     * Get a unique identifier for rate limiting based on IP and user agent
     * 
     * This combines IP address and user agent to create a more accurate identifier
     * while still being reasonably anonymous. It helps prevent bypassing via user agent
     * rotation while allowing multiple users behind the same NAT.
     *
     * @return string Hashed identifier
     */
    private function getRateLimitIdentifier(): string
    {
        $ipAddress = $this->getClientIp();
        $userAgent = $this->wpService->sanitizeTextField($_SERVER['HTTP_USER_AGENT'] ?? 'unknown');
        return md5($ipAddress . $userAgent);
    }

    /**
     * Get the client IP address, respecting proxy headers
     *
     * @return string IP address
     */
    private function getClientIp(): string
    {
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $ip = trim($ips[0]);
        } elseif (!empty($_SERVER['HTTP_X_REAL_IP'])) {
            $ip = $_SERVER['HTTP_X_REAL_IP'];
        } else {
            $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            return $ip;
        }
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }
}