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
    $url = str_replace('\\', '', $url);
    
    if (strpos($url, '//') === 0) {
        $url = 'https:' . $url;
    }
    
    // Parse URL to get components
    $parsed = parse_url($url);
    if ($parsed === false) {
        return null;
    }
    
    // Reconstruct URL preserving port
    $result = '';
    if (isset($parsed['scheme'])) {
        $result .= strtolower($parsed['scheme']) . '://';
    }
    if (isset($parsed['host'])) {
        $result .= strtolower($parsed['host']);
        if (isset($parsed['port'])) {
            $result .= ':' . $parsed['port'];
        }
    }
    if (isset($parsed['path'])) {
        $result .= $parsed['path'];
    }
    if (isset($parsed['query'])) {
        $result .= '?' . $parsed['query'];
    }
    if (isset($parsed['fragment'])) {
        $result .= '#' . $parsed['fragment'];
    }
    
    return $result;
  }
}