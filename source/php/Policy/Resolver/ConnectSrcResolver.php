<?php 

namespace WPMUSecurity\Policy\Resolver;

use WPMUSecurity\Policy\DomWrapperInterface;

class ConnectSrcResolver implements DomainResolverInterface {

  public function resolve(DomWrapperInterface $dom): array {
      $domains = [];

      foreach ($dom->getAttributesWithUrls() as $attr) {
          if (!$attr instanceof \DOMAttr || $attr->name === 'href') {
              continue;
          }

          $value = $attr->value;

          if (filter_var($value, FILTER_VALIDATE_URL)) {
              $domains[] = parse_url($value, PHP_URL_HOST);
              continue;
          }

          if ($this->isJson($value)) {
              $decoded = json_decode($value, true);
              if (is_array($decoded)) {
                  $domains = array_merge($domains, $this->extractUrlsFromArray($decoded));
              }
          }

          if ($this->isSerialized($value)) {
              $unescaped = str_replace('\/', '/', $value);
              $unserialized = @unserialize($unescaped);
              if (is_array($unserialized)) {
                  $domains = array_merge($domains, $this->extractUrlsFromArray($unserialized));
              }
          }

          if (preg_match_all('/https?:\/\/[^\s"\'>]+/i', $value, $matches)) {
              foreach ($matches[0] as $url) {
                  $domains[] = parse_url($url, PHP_URL_HOST);
              }
          }
      }

      return array_values(array_filter(array_unique($domains)));
  }

  /**
   * Extract URLs from an array, recursively.
   *
   * @param array $data The array to search for URLs.
   * @return array An array of unique hostnames extracted from URLs.
   */
  private function extractUrlsFromArray(array $data): array {
      $urls = [];

      array_walk_recursive($data, function ($value) use (&$urls) {
          if (filter_var($value, FILTER_VALIDATE_URL)) {
              $urls[] = parse_url($value, PHP_URL_HOST);
          }
      });

      return $urls;
  }

  /**
   * Check if a string is valid JSON.
   *
   * @param string $string The string to check.
   * @return bool True if the string is valid JSON, false otherwise.
   */
  private function isJson(string $string): bool {
      if(function_exists('json_validate')) {
          return json_validate($string);
      }
      json_decode($string);
      return json_last_error() === JSON_ERROR_NONE;
  }

  /**
   * Check if a string is serialized.
   *
   * @param string $string The string to check.
   * @return bool True if the string is serialized, false otherwise.
   */
  private function isSerialized(string $string): bool {
      return $string === 'b:0;' || @unserialize(str_replace('\/', '/', $string)) !== false;
  }
}