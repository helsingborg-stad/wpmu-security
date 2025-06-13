<?php

namespace WPMUSecurity\Policy;

use DOMDocument;
use DOMXPath;

class DomWrapper implements DomWrapperInterface {
    private DOMXPath $xpath;

    /**
     * DomWrapper constructor.
     *
     * Initializes the DOMXPath object with the provided DOMDocument.
     *
     * @param DOMDocument $dom The DOMDocument to wrap.
     */
    public function __construct(private DOMDocument $dom) {
        $this->xpath = new DOMXPath($dom);
    }

    /**
     * Executes an XPath query on the DOM and returns the result.
     *
     * This method allows you to run any XPath query against the DOM
     * and returns the resulting node list.
     *
     * @param string $xpath The XPath query to execute.
     * @return \DOMNodeList The result of the XPath query.
     */
    public function query(string $xpath): \DOMNodeList {
        return $this->xpath->query($xpath);
    }

    /**
     * Returns all inline CSS styles from the DOM.
     *
     * This method retrieves all <style> elements in the DOM and returns
     * their content as an array of strings.
     *
     * @return array An array of strings containing inline CSS styles.
     */
    public function getInlineCss(): array {
        $styles = [];
        foreach ($this->xpath->query('//style') as $style) {
            $styles[] = $style->nodeValue;
        }
        return $styles;
    }

    /**
     * Returns all attributes that contain URLs in the DOM.
     *
     * This method retrieves all attributes from all elements in the DOM
     * and returns those that contain URLs.
     *
     * @return array An array of DOMAttr objects containing URLs.
     */
    public function getAttributesWithUrls(): array {
        $attributes = [];
        foreach ($this->xpath->query('//*') as $element) {
            if ($element->hasAttributes()) {
                foreach ($element->attributes as $attr) {
                    $attributes[] = $attr; // DOMAttr object
                }
            }
        }
        return $attributes;
    }
}