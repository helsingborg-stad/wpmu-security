<?php 

namespace WPMUSecurity\Policy\Resolver;

use WPMUSecurity\Policy\DomWrapperInterface;
use WPMUSecurity\Policy\UrlInterface;

class ImgSrcResolver implements DomainResolverInterface {
    use HostWithPortTrait;

    private const IMG_SUFFIXES = [
        'jpg', 'jpeg', 'png', 'gif', 'webp', 'avif', 'svg',
        'bmp', 'ico', 'tiff', 'tif', 'heic', 'heif'
    ];

    public function __construct(private UrlInterface $urlHelper) {}

    public function resolve(DomWrapperInterface $dom): array {
        $images = $this->getImagesFromTags($dom);
        $inlineImages = $this->getImagesFromInlineScripts($dom);
        $domains = array_merge($images, $inlineImages);
        $domains[] = "data:";
        return array_values(array_filter(array_unique($domains)));
    }

    /**
     * Extracts image domains from <img> and <picture> tags.
     *
     * @param DomWrapperInterface $dom
     * @return array
     */
    public function getImagesFromTags($dom): array {
        $domains = [];
        foreach ($dom->query('//img[@src]') as $node) {
            if (!$node instanceof \DOMElement) {
                continue;
            } 
            $src = $node->getAttribute('src');
            $host = $this->extractHostWithPort($src);
            if ($host) {
                $domains[] = $host;
            }
        }

        foreach ($dom->query('//picture/source[@srcset]') as $source) {
            if (!$source instanceof \DOMElement) {
                continue;
            }
            $urls = explode(',', $source->getAttribute('srcset'));
            foreach ($urls as $urlPart) {
                $url = trim(explode(' ', $urlPart)[0]);
                if (preg_match('/\.(?:' . implode('|', self::IMG_SUFFIXES) . ')$/i', $url)) {
                    $url = $this->urlHelper->normalize($url);
                    $host = $this->extractHostWithPort($url);
                    if ($host) {
                        $domains[] = $host;
                    }
                }
            }
        }

        return array_values(array_filter(array_unique($domains)));
    }

  /**
   * Extracts image from <script> URLS HERE </script> tags, including inline scripts.
   *
   * @param DomWrapperInterface $dom
   * @return array
   */
  private function getImagesFromInlineScripts($dom) {
      $domains = [];

      foreach ($dom->query('//script') as $node) {
          if (!$node instanceof \DOMElement) {
              continue;
          }

          if (!$node->hasAttribute('src') && trim($node->textContent) !== '') {
              if (preg_match_all('/https?:\\\\*\/\\\\*\/[a-zA-Z0-9\-._~:\/?#\[\]@!$&\'()*+,;=%\\\\]+/i', $node->textContent, $matches)) {
                  foreach ($matches[0] as $url) {
                      if (!preg_match('/\.(?:' . implode('|', self::IMG_SUFFIXES) . ')$/i', $url)) {
                          continue;
                      }
                      $normalizedUrl = $this->urlHelper->normalize($url);
                      if ($normalizedUrl) {
                          $host = $this->extractHostWithPort($normalizedUrl);
                          if ($host) {
                              $domains[] = $host;
                          }
                      }
                  }
              }
          }

      }

      return array_values(array_filter(array_unique($domains)));
  }
}