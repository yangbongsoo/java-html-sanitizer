package org.owasp.html;

import junit.framework.TestCase;
import org.junit.Test;

public class AllowUrlProtocolsTest extends TestCase {

  // beforePolicy : X
  // newPolicy : X
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

  // beforePolicy : X
  // newPolicy : allow
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

  // beforePolicy : X
  // newPolicy : disallow
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

  // beforePolicy : allow
  // newPolicy : X
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

  // beforePolicy : allow
  // newPolicy : allow
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

  // beforePolicy : allow
  // newPolicy : allow
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

  // beforePolicy : allow
  // newPolicy : disallow
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

  // beforePolicy : allow
  // newPolicy : disallow
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

  // beforePolicy : disallow
  // newPolicy : X
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

  // beforePolicy : disallow
  // newPolicy : X
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

  // beforePolicy : disallow
  // newPolicy : allow
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

  // beforePolicy : disallow
  // newPolicy : disallow
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

  // beforePolicy : disallow
  // newPolicy : disallow
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
}
