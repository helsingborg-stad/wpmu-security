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
     * @testdox Test dataset result table:
     */
    public function testThatWeCanPrintATableOfDomains()
    {
        $testDocument           = $this->testHTMLDocumentProvider();
        $contentSecurityPolicy  = new ContentSecurityPolicy(
          new FakeWpService()
        );
        $result   = $contentSecurityPolicy->getCategorizedDomainsFromMarkup($testDocument);
        $this->printPolicyTable($result);
        $this->assertIsArray($result);
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
          ['picture3.test'],
          ['form1.test'],
          ['form2.test'],
          ['attribute.img1.test'],
          ['attribute.img2.test'],
          ['attribute.iframe2.test'],
          ['attribute.object2.test'],
          ['attribute.embed2.test'],
          ['attribute.video1.test'],
          ['attribute.audio2.test'],
          ['attribute.form1.test'],
          ['attribute.alink2.test'],
          ['data1.test'],
          ['data2.test'],
          ['data3.test'],
          ['data4.test'],
          ['data5.test'],
          ['data6.test'],
          ['fonts1.test'],
          ['fonts2.test'],
          ['imageindatatag.subdomain.domain.se'],
          ['stats.matomo.com']
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

  /**
   * Print a table of all domains found in the HTML document.
   * This is useful for debugging and verifying the domains extracted from the document.
   */
  private function printPolicyTable(array $policy): void
  {
      $headers = ['Directive', 'Allowed Sources'];
      $maxDirectiveLength = strlen($headers[0]);
      $rows = [];

      // Prepare rows and calculate width
      foreach ($policy as $directive => $sources) {
          $chunks = array_chunk($sources, 5);
          $lines = array_map(fn($chunk) => implode(', ', $chunk), $chunks);
          $cell = implode("\n", $lines);

          $maxDirectiveLength = max($maxDirectiveLength, strlen($directive));
          $rows[] = [$directive, $cell];
      }

      // Calculate max height-adjusted width of sources
      $maxSourcesLength = strlen($headers[1]);
      foreach ($rows as [$_, $cell]) {
          $maxSourcesLength = max($maxSourcesLength, ...array_map('strlen', explode("\n", $cell)));
      }

      $border = '+' . str_repeat('-', $maxDirectiveLength + 2) . '+' . str_repeat('-', $maxSourcesLength + 2) . '+';

      // Print table
      echo "\n$border\n";
      echo '| ' . str_pad($headers[0], $maxDirectiveLength) . ' | ' . str_pad($headers[1], $maxSourcesLength) . " |\n";
      echo "$border\n";

      foreach ($rows as [$directive, $sources]) {
          $sourceLines = explode("\n", $sources);
          foreach ($sourceLines as $i => $line) {
              echo '| '
                  . str_pad($i === 0 ? $directive : '', $maxDirectiveLength)
                  . ' | '
                  . str_pad($line, $maxSourcesLength)
                  . " |\n";
          }
      }

      echo "$border\n\n";
  }
}