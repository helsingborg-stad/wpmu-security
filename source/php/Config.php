<?php

namespace WPMUSecurity;

use WpService\WpService;
class Config
{
  public function __construct(private string $filterPrefix, private WpService $wpService)
  {
  }

  /**
   * Get HSTS max age in seconds.
   *
   * @return int
   */
  public function getHstsMaxAge():int
  {
    return $this->wpService->applyFilters(
      $this->createFilterKey(__FUNCTION__),
      31536000
    );
  }

  /**
   * Get the filter prefix.
   * 
   * @return string
   */
  public function getFilterPrefix(): string
  {
    if (!isset($this->filterPrefix)) {
      $this->filterPrefix = 'WPMUSecurity/Config/';
    }
    return rtrim($this->filterPrefix, "/") . "/";
  }

  /**
   * Create a prefix for image conversion filter.
   *
   * @return string
   */
  public function createFilterKey(string $filter = ""): string
  {
    return $this->getFilterPrefix() . ucfirst($filter);
  }
}