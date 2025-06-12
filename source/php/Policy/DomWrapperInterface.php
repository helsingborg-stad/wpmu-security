<?php 
namespace WPMUSecurity\Policy;

interface DomWrapperInterface {
  public function query(string $xpath): \DOMNodeList;
  public function getInlineCss(): array;
  public function getAttributesWithUrls(): array;
}