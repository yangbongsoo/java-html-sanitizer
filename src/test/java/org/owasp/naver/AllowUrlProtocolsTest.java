package org.owasp.naver;

import junit.framework.TestCase;
import org.junit.Test;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;

public class AllowUrlProtocolsTest extends TestCase {

  // before : X
  // after : X
  @Test
  public void testAllowUrlProtocol1() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .toFactory();

    String input = "<a href='http://example.com'>Hi</a>";
    assertEquals("Hi", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("Hi", afterPolicy.sanitize(input));
  }

  // before : X
  // after : allow
  @Test
  public void testAllowUrlProtocol2() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .toFactory();

    String input = "<a href='http://example.com'>Hi</a>";
    assertEquals("Hi", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .allowUrlProtocols("http")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("<a href='http://example.com'>Hi</a>", afterPolicy.sanitize(input));
  }

  // before : X
  // after : disallow
  @Test
  public void testAllowUrlProtocol3() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .toFactory();

    String input = "<a href='http://example.com'>Hi</a>";
    assertEquals("Hi", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .disallowUrlProtocols("http")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("Hi", afterPolicy.sanitize(input));
  }

  // before : allow
  // after : X
  @Test
  public void testAllowUrlProtocol4() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .allowUrlProtocols("http")
            .toFactory();

    String input = "<a href='http://example.com'>Hi</a>";
    assertEquals("<a href=\"http://example.com\">Hi</a>", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("<a href=\"http://example.com\">Hi</a>", afterPolicy.sanitize(input));
  }

  // before : allow
  // after : allow
  @Test
  public void testAllowUrlProtocol5() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .allowUrlProtocols("http")
            .toFactory();

    String input = "<a href='http://example.com'>Hi</a>";
    assertEquals("<a href=\"http://example.com\">Hi</a>", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .allowUrlProtocols("http")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("<a href=\"http://example.com\">Hi</a>", afterPolicy.sanitize(input));
  }

  // before : allow
  // after : allow
  @Test
  public void testAllowUrlProtocol5_1() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .allowUrlProtocols("http")
            .toFactory();

    String input = "<a href='http://example.com'>Hi</a>";
    assertEquals("<a href=\"http://example.com\">Hi</a>", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .allowUrlProtocols("https")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("<a href=\"http://example.com\">Hi</a>", afterPolicy.sanitize(input));
  }

  // before : allow
  // after : disallow
  @Test
  public void testAllowUrlProtocol6() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .allowUrlProtocols("http")
            .toFactory();

    String input = "<a href='http://example.com'>Hi</a>";
    assertEquals("<a href=\"http://example.com\">Hi</a>", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .disallowUrlProtocols("http", "https")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("Hi", afterPolicy.sanitize(input));
  }

  // before : allow
  // after : disallow
  @Test
  public void testAllowUrlProtocol6_1() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .allowUrlProtocols("http")
            .toFactory();

    String input = "<a href='http://example.com'>Hi</a>";
    assertEquals("<a href=\"http://example.com\">Hi</a>", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .disallowUrlProtocols("https")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("Hi", afterPolicy.sanitize(input));
  }

  // before : disallow
  // after : X
  @Test
  public void testAllowUrlProtocol7() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .disallowUrlProtocols("http")
            .toFactory();

    String input = "<a href='http://example.com'>Hi</a>";
    assertEquals("Hi", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("Hi", afterPolicy.sanitize(input));
  }

  // before : disallow
  // after : X
  @Test
  public void testAllowUrlProtocol7_1() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .disallowUrlProtocols("http", "https")
            .toFactory();

    String input = "<a href='https://example.com'>Hi</a>";
    assertEquals("Hi", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("Hi", afterPolicy.sanitize(input));
  }

  // before : disallow
  // after : allow
  @Test
  public void testAllowUrlProtocol8() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .disallowUrlProtocols("http")
            .toFactory();

    String input = "<a href='https://example.com'>Hi</a>";
    assertEquals("Hi", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .allowUrlProtocols("http")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("<a href=\"http://example.com\">Hi</a>", afterPolicy.sanitize(input));
  }

  // before : disallow
  // after : disallow
  @Test
  public void testAllowUrlProtocol9() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .disallowUrlProtocols("http")
            .toFactory();

    String input = "<a href='https://example.com'>Hi</a>";
    assertEquals("Hi", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .disallowUrlProtocols("http")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("Hi", afterPolicy.sanitize(input));
  }

  // before : disallow
  // after : disallow
  @Test
  public void testAllowUrlProtocol9_1() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .disallowUrlProtocols("http")
            .toFactory();

    String input = "<a href='https://example.com'>Hi</a>";
    assertEquals("Hi", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .disallowUrlProtocols("https")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("Hi", afterPolicy.sanitize(input));
  }

  //////

  @Test
  public void testaaa() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("p")
            .toFactory();

    String input = "<p>pText</p>\n<b>bText</b>\n<i>iText</i>";
    System.out.println(beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .allowElements("b","i")
//            .disallowElements("p")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);
    System.out.println(afterPolicy.sanitize(input));
  }


//  @Test
//  public void testHtmlTagSkipPolicy15() {
//    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
//            .allowElements("a", "p")
//            .allowWithoutAttributes("a")
//            .toFactory();
//
//    String pTagString = "<a>Hi</a>";
//    String resultString = beforePolicy.sanitize(pTagString);
//    assertEquals("<a>Hi</a>", resultString);
//
//    PolicyFactory afterPolicy = beforePolicy.and(new HtmlPolicyBuilder()
//            .allowElements("a")
//            .disallowWithoutAttributes("a")
//            .toFactory());
//
//    resultString = afterPolicy.sanitize(pTagString);
//    assertEquals("Hi", resultString);
//  }
}
