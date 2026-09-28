<?php

namespace WPMUSecurity\Headers;

use WpService\WpService;

class ResponseSecurityHeaders
{
    public function __construct(private WpService $wpService) {}

    public function addHooks(): void
    {
        $this->wpService->addAction('send_headers', [$this, 'addHeaders']);
    }

    public function addHeaders(): void
    {
        if (headers_sent()) {
            return;
        }

        $existingHeaders = array_map(
            static fn(string $header): string => strtolower(trim(explode(':', $header, 2)[0])),
            headers_list(),
        );

        $defaults = [
            'Referrer-Policy' => 'strict-origin-when-cross-origin',
            'X-Content-Type-Options' => 'nosniff',
        ];

        foreach ($defaults as $name => $value) {
            if (!in_array(strtolower($name), $existingHeaders, true)) {
                header("{$name}: {$value}");
            }
        }
    }
}
