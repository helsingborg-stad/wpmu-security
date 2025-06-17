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

## ⚙️ Configuration

This plugin is designed to be hassle free, however if you like to add domains that are not detected in the content security policy. Please use the following filter: 

```
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