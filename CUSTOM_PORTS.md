# Custom Port Number Support

This document describes the changes made to support custom port numbers in the WPMU Security plugin.

## Problem Description

When running WordPress on a custom port (e.g., `localhost:8080` for development), many security features broke because the plugin was not properly handling port numbers in URLs. This affected:

- Content Security Policy (CSP) headers
- CORS headers  
- Subresource Integrity (SRI) checks
- Domain matching and URL parsing

## Solution Overview

The fix involved updating URL normalization and domain extraction throughout the plugin to preserve and correctly handle port numbers.

## Changes Made

### 1. URL Normalization (`Policy/Url.php`)

**Before:**
```php
public function normalize(string $url): ?string
{
    $url = str_replace('\\/', '/', $url);
    $url = rtrim($url, '/');
    $url = strtolower($url);
    $url = str_replace('\\', '', $url);
    if (strpos($url, '//') === 0) {
        $url = 'https:' . $url;
    }
    return $url;
}
```

**After:**
```php
public function normalize(string $url): ?string
{
    $url = str_replace('\\/', '/', $url);
    $url = rtrim($url, '/');
    $url = str_replace('\\', '', $url);
    
    if (strpos($url, '//') === 0) {
        $url = 'https:' . $url;
    }
    
    // Parse URL to get components
    $parsed = parse_url($url);
    if ($parsed === false) {
        return null;
    }
    
    // Reconstruct URL preserving port
    $result = '';
    if (isset($parsed['scheme'])) {
        $result .= strtolower($parsed['scheme']) . '://';
    }
    if (isset($parsed['host'])) {
        $result .= strtolower($parsed['host']);
        if (isset($parsed['port'])) {
            $result .= ':' . $parsed['port'];
        }
    }
    if (isset($parsed['path'])) {
        $result .= $parsed['path'];
    }
    // ... rest of URL components
    
    return $result;
}
```

### 2. CSP Domain Resolvers

Created a shared trait for consistent port handling:

**New: `Policy/Resolver/HostWithPortTrait.php`**
```php
trait HostWithPortTrait
{
    protected function extractHostWithPort(string $url): ?string
    {
        $parsed = parse_url($url);
        if ($parsed === false || !isset($parsed['host'])) {
            return null;
        }
        
        $host = $parsed['host'];
        if (isset($parsed['port'])) {
            $host .= ':' . $parsed['port'];
        }
        
        return $host;
    }
}
```

**Updated all resolvers** (`ScriptSrcResolver`, `StyleSrcResolver`, etc.) to:
- Use the `HostWithPortTrait`
- Extract `host:port` instead of just `host`
- Handle both custom ports and standard ports correctly

**Before:**
```php
$domains[] = parse_url($url, PHP_URL_HOST);
```

**After:**
```php
$host = $this->extractHostWithPort($url);
if ($host) {
    $domains[] = $host;
}
```

### 3. Headers and SRI

The CORS headers and SubresourceIntegrity classes already used `wpService->getHomeUrl()` which includes ports, so they work correctly with the URL normalization fixes.

## Test Coverage

Added comprehensive tests covering:

- URL normalization with various port scenarios
- CSP domain extraction from HTML with mixed port/non-port URLs
- CSP header generation including port numbers
- SubResourceIntegrity domain matching with ports
- CORS header generation with ports
- Full integration tests simulating WordPress on custom ports

## Usage Examples

### Development Environment
WordPress running on `http://localhost:8080` will now correctly:

- Generate CSP headers: `script-src 'self' localhost:8080 cdn.example.com:8443;`
- Set CORS headers: `Access-Control-Allow-Origin: http://localhost:8080`
- Match local assets for SRI: `http://localhost:8080/wp-content/...`

### Custom HTTPS Ports
WordPress running on `https://example.com:8443` will correctly:

- Handle all external resources with custom ports in CSP
- Allow cross-origin requests from the correct port
- Generate proper SRI hashes for local assets

## Backwards Compatibility

All changes are backwards compatible:
- Standard ports (80/443) continue to work as before
- URLs without ports are handled correctly
- Existing CSP filter hooks continue to work

## Testing

Run the integration test to verify port handling:
```bash
php /tmp/integration_test.php
```

This test simulates a complete WordPress environment with custom ports and validates all components work together correctly.