# 🔐 WordPress Security Hardening Plugin

A lightweight WordPress plugin focused on modern security hardening best practices without unnecessary bloat.

## 🚀 Features

- ✅ Generic login error messages (prevent user enumeration)
- ✅ Generic password reset responses
- ✅ HTTP Strict Transport Security (HSTS)
- ✅ CORS configuration
- ✅ Subresource Integrity (SRI) for scripts and styles
- ✅ XML-RPC disabling
- ✅ Comment sanitization (anti-XSS)
- ✅ Content Security Policy (CSP)
- ✅ **Custom port number support** (development environments, custom setups)

## ⚙️ Configuration

This plugin is designed to be hassle free, however if you like to add domains that are not detected in the content security policy. Please use the following filter: 

```php
add_filter(
    'WpSecurity/Csp',
    function ($domains) {
        if(!isset($domains['connect-src'])) {
            $domains['connect-src'] = [];
        }
        $domains['connect-src'][] = 'https://*.domain.com';
        $domains['connect-src'][] = 'https://*.domain.net';
        return $domains;
    }
);
```

## 🔧 Custom Port Support

The plugin fully supports WordPress installations running on custom ports (e.g., `localhost:8080` for development). All security features work correctly with custom ports:

- ✅ CSP headers include port numbers in domain policies
- ✅ CORS headers respect the full URL with port
- ✅ SRI verification works with local assets on custom ports
- ✅ All URL parsing and domain matching handles ports correctly

No additional configuration is needed - the plugin automatically detects and handles custom ports from your WordPress site URL.

For detailed information about custom port support, see [CUSTOM_PORTS.md](CUSTOM_PORTS.md).