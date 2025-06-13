<?php

namespace WPMUSecurity\Policy;

class Url implements UrlInterface
{
  /**
   * @inheritdoc
   */
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
}