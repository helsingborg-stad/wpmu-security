<?php

namespace WPMU\Security\RateLimit\Api;

use WPMUSecurity\HookableInterface;
use WP_REST_Request;
use WPMUSecurity\RateLimit\RateLimit;

class RateLimitPostRequest implements HookableInterface
{
  public function __construct(private RateLimit $rateLimit)
  {
  }

  public function addHooks(): void
  {
    $this->wpService->addAction(
      'rest_api_init',
      [$this, 'registerRateLimitEndpoint']
    );
  }

  /**
   * Register the rate limit.
   *
   * @return void
   */
  public function rateLimitRequest(WP_REST_Request $request)
  {
      $identifier = $this->rateLimit->getRateLimitIdentifier();
      $action     = $request->get_route();
      
      if ($this->rateLimit->isRateLimited($identifier, $action)) {
        new WP_Error(
          'rate_limit_exceeded',
          $this->wpService->__('Too many requests. Please try again later.', 'wpmu-security'),
          ['status' => 429]
        );
      }
  }
}