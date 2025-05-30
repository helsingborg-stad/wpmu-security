<?php

namespace WPMUSecurity\Policy;

use PHPUnit\Framework\TestCase;
use WpService\Implementations\FakeWpService;

class ContentSecurityPolicyTest extends TestCase {

    /**
     * @testdox class can be instantiated
     */
    public function testClassCanBeInstantiated() {
        $wpService = new FakeWpService();
        $this->assertInstanceOf( ContentSecurityPolicy::class, new ContentSecurityPolicy(
            $wpService
        ));
    }

    /**
     * @testdox getDomainsFromMarkup returns no a-element urls.
     */
    public function testNoLinkElementsAreRecivedFromDocument() {
      $testDocument           = $this->testHTMLDocumentProvider();
      $contentSecurityPolicy  = new ContentSecurityPolicy(
        new FakeWpService()
      );

      $result   = $contentSecurityPolicy->getCategorizedDomainsFromMarkup($testDocument);
      $result   = array_unique(array_merge(...array_values($result)));

      $this->assertIsArray($result);
      $this->assertNotContains('alink1.test', $result);
      $this->assertNotContains('alink2.test', $result);
    }

    /**
     * @testdox getDomainsFromMarkup returns all expected domains.
     * @dataProvider domainMarkupProvider
     */
    public function testExpectedDomainsAreRecivedFromDocument(string $expectedDomain)
    {
        $testDocument           = $this->testHTMLDocumentProvider();
        $contentSecurityPolicy  = new ContentSecurityPolicy(
          new FakeWpService()
        );

        $result   = $contentSecurityPolicy->getCategorizedDomainsFromMarkup($testDocument);
        $result   = array_unique(array_merge(...array_values($result)));

        $this->assertIsArray($result);
        $this->assertContains($expectedDomain, $result);
    }

    /**
     * @testdox getDomainsFromMarkup returns all expected domains.
     */
    public function testGetDomainsFromMarkupReturnsAllExpectedDomains() {
        $testDocument           = $this->testHTMLDocumentProvider();
        $contentSecurityPolicy  = new ContentSecurityPolicy(
          new FakeWpService()
        );

        $result   = $contentSecurityPolicy->getCategorizedDomainsFromMarkup($testDocument);
        $result   = array_unique(array_merge(...array_values($result)));

        $this->assertIsArray($result);
        $this->assertCount(36, $result);
    }

    /**
     * @testdox getDomainsFromMarkup returns expected number of domains containing a given substring.
     * @dataProvider domainSubstringCountProvider
     */
    public function testGetDomainsResultsInExpectedCountForSubstring(string $substring, int $expectedCount) {
        $testDocument           = $this->testHTMLDocumentProvider();
        $contentSecurityPolicy  = new ContentSecurityPolicy(
          new FakeWpService()
        );

        $result   = $contentSecurityPolicy->getCategorizedDomainsFromMarkup($testDocument);
        $result   = array_unique(array_merge(...array_values($result)));

        $filteredDomains = array_filter($result, function ($domain) use ($substring) {
          return strpos($domain, $substring) !== false;
        });

        $this->assertCount($expectedCount, $filteredDomains);
    }

    /**
     * Provides a list of substrings and their expected counts in the list of domains.
     * 
     * @return array An array of arrays, each containing a substring and its expected count.
     */
    public function domainSubstringCountProvider(): array {
      return [
        ['css', 2],
        ['js', 2],
        ['img', 4],
        ['iframe', 3],
        ['object', 3],
        ['embed', 3],
        ['video', 3],
        ['audio', 3],
        ['picture', 2],
        ['form', 3],
        ['data', 6],
      ];
    }

    /**
     * Provides a list of domains that are expected to be found in the HTML document.
     * 
     * @return array An array of arrays, each containing a domain string.
     */
    private function domainMarkupProvider(): array {
      return [
          ['css1.test'],
          ['css2.test'],
          ['js1.test'],
          ['js2.test'],
          ['img1.test'],
          ['img2.test'],
          ['iframe1.test'],
          ['iframe2.test'],
          ['object1.test'],
          ['object2.test'],
          ['embed1.test'],
          ['embed2.test'],
          ['video1.test'],
          ['video2.test'],
          ['audio1.test'],
          ['audio2.test'],
          ['picture1.test'],
          ['picture2.test'],
          ['form1.test'],
          ['form2.test'],
          ['data1.test'],
          ['data2.test'],
          ['data3.test'],
          ['data4.test'],
          ['data5.test'],
          ['data6.test']
      ];
  }

  /**
   * Provides a sample HTML document for testing.
   *
   * @return string The HTML content as a string.
   */
  private function testHTMLDocumentProvider(): string {
      return file_get_contents(__DIR__ . '/ContentSecurityPolicyTest.html');
  }
}