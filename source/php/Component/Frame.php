<?php

declare(strict_types=1);

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

    public function displayAcceptance($srcURL): bool
    {
        $whiteList = $this->acfService->getField(self::ACF_OPTION_BYPASS_ACCEPTANCE, 'option', false);
        if (is_array($whiteList)) {
            $srcHost = parse_url($srcURL, PHP_URL_HOST);
            foreach ($whiteList as $row) {
                if ($srcHost === $row[self::ACF_BYPASS_KEY]) {
                    return false;
                }
            }
        }
        return true;
    }
}
