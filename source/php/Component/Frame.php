<?php

namespace WPMUSecurity\Component;

use AcfService\AcfService;
use WpService\WpService;

class Frame
{
    private const ACF_BYPASS_KEY = 'field_69ba7a3ae80fc';
    private const ACF_OPTION_BYPASS_ACCEPTANCE = 'security_csp_bypass_user_accept';

    public function __construct(
        private WpService $wpService,
        private AcfService $acfService,
    ) {}

    /**
     * Adds hooks for the iframe functionality.
     *
     * @return void
     */
    public function addHooks()
    {
        $this->wpService->addFilter('ComponentLibrary/Component/Iframe/DisplayAcceptance', [$this, 'displayAcceptance'], 10, 1);
    }

    public function displayAcceptance($url)
    {
        $domains = $this->acfService->getField(self::ACF_OPTION_BYPASS_ACCEPTANCE, 'option', false);
        if (is_array($domains)) {
            foreach ($domains as $domain) {
                $parts = parse_url($domain[self::ACF_BYPASS_KEY]);
                if ($parts['host'] === $domain) {
                    return false;
                }
            }
        }
        return true;
    }
}
