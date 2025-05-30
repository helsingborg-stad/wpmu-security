<?php

namespace WPMUSecurity\Policy;

use PHPUnit\Framework\TestCase;
use WP_Error;
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
    public function testIframeDomainsAreRecivedFromDocument(string $expectedDomain)
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
        $this->assertCount(20, $result); // 20 unique domains expected
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
      ];
  }
}