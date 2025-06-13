<?php

namespace WPMUSecurity\Policy;

interface UrlInterface
{
  /**
   * Normalize a URL by removing trailing slashes, lowercasing the scheme and host,
   * and removing default ports.
   *
   * @param string $url
   * @return string|null Normalized URL or null if invalid
   */
  public function normalize(string $url): ?string;
}