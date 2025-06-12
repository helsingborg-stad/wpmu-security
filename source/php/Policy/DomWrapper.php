<?php

namespace WPMUSecurity\Policy;

use DOMDocument;
use DOMXPath;

class DomWrapper implements DomWrapperInterface {
    private DOMXPath $xpath;

    public function __construct(private DOMDocument $dom) {
        $this->xpath = new DOMXPath($dom);
    }

    public function query(string $xpath): \DOMNodeList {
        return $this->xpath->query($xpath);
    }

    public function getInlineCss(): array {
        $styles = [];
        foreach ($this->xpath->query('//style') as $style) {
            $styles[] = $style->nodeValue;
        }
        return $styles;
    }

    public function getAttributesWithUrls(): array {
        $attributes = [];
        foreach ($this->xpath->query('//*') as $element) {
            if ($element->hasAttributes()) {
                foreach ($element->attributes as $attr) {
                    $attributes[] = $attr->value;
                }
            }
        }
        return $attributes;
    }
}