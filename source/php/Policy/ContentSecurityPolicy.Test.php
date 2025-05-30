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
      $result = $contentSecurityPolicy->getDomainsFromMarkup(
        $testDocument
      );

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
        $testDocument = $this->testHTMLDocumentProvider();
        $contentSecurityPolicy = new ContentSecurityPolicy(new FakeWpService());
        $result = $contentSecurityPolicy->getDomainsFromMarkup($testDocument);

        $this->assertIsArray($result);
        $this->assertContains($expectedDomain, $result);
    }

    /**
     * @testdox getDomainsFromMarkup returns all expected domains.
     */
    public function testGetDomainsFromMarkupReturnsAllExpectedDomains() {
        $testDocument = $this->testHTMLDocumentProvider();
        $contentSecurityPolicy = new ContentSecurityPolicy(new FakeWpService());
        $result = $contentSecurityPolicy->getDomainsFromMarkup($testDocument);

        $this->assertIsArray($result);
        $this->assertCount(36, $result);
    }

    /**
     * @testdox getDomainsFromMarkup and getCategorizedDomainsFromMarkup return the same domains.
     */
    public function testGetDomainsFromMarkupReturnsSameDomainsAsGetCategorizedDomainsFromMarkup() {
        $testDocument = $this->testHTMLDocumentProvider();
        $contentSecurityPolicy = new ContentSecurityPolicy(new FakeWpService());

        $resultFromMarkup       = $contentSecurityPolicy->getDomainsFromMarkup($testDocument);
        $resultFromCategorized  = $contentSecurityPolicy->getCategorizedDomainsFromMarkup($testDocument);
        var_dump($resultFromCategorized);

        $resultFromCategorized  = array_unique(array_merge(...array_values($resultFromCategorized)));

        usort($resultFromMarkup,      'strcasecmp');
        usort($resultFromCategorized, 'strcasecmp');
        
        $this->assertEqualsCanonicalizing($resultFromCategorized, $resultFromMarkup);
    }

    /**
     * @testdox getDomainsFromMarkup returns expected number of domains containing a given substring.
     * @dataProvider domainSubstringCountProvider
     */
    public function testGetDomainsResultsInExpectedCountForSubstring(string $substring, int $expectedCount) {
      $testDocument = $this->testHTMLDocumentProvider();
      $contentSecurityPolicy = new ContentSecurityPolicy(new FakeWpService());
      $result = $contentSecurityPolicy->getDomainsFromMarkup($testDocument);

      $filteredDomains = array_filter($result, function ($domain) use ($substring) {
        return strpos($domain, $substring) !== false;
      });

      $this->assertCount($expectedCount, $filteredDomains);
    }

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

    private function testHTMLDocumentProvider(): string {
        return file_get_contents(__DIR__ . '/ContentSecurityPolicyTest.html');
    }

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
}