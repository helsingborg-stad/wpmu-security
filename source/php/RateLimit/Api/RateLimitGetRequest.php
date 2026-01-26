<?php

namespace WPMUSecurity\RateLimit\Api;

use WPMUSecurity\HookableInterface;
use WP_REST_Request;
use WPMUSecurity\RateLimit\RateLimit;
use WP_Error;
use WpService\WpService;
use WP_REST_Server;

class RateLimitGetRequest implements HookableInterface
{
  /**
   * Allow maximum 600 requests per 10 minutes towards any given GET endpoint.
   * 
   */
  private const MAX_REQUESTS = 600;
  private const TIME_WINDOW  = 600;

  /**
   * Constructor
   *
   * @param WpService $wpService
   * @param RateLimit $rateLimit
   */
  public function __construct(private WpService $wpService, private RateLimit $rateLimit){}

  /**
   * Register the rate limit endpoint.
   *
   * @return void
   */
  public function addHooks(): void
  {
    $this->wpService->addFilter(
      'rest_pre_dispatch',
      [$this, 'rateLimitRequest'],
      10, 
      3
    );
  }

  /**
   * Register the rate limit.
   *
   * @return void
   */
  public function rateLimitRequest($result,  WP_REST_Server $server, WP_REST_Request $request)
  {
      if($request->get_method() !== 'GET' && $request->get_method() !== 'OPTIONS') {
          return $result;
      }
      $isBlocked = $this->rateLimit->init(self::MAX_REQUESTS, self::TIME_WINDOW, $request->get_route());
      if ($isBlocked instanceof WP_Error) {
          return $isBlocked;
      }
      return $result;
  }
}