package org.owasp.naver;

import junit.framework.TestCase;
import org.junit.Test;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;

public class ProtocolTest extends TestCase {

  // before : X
  // after : X
  @Test
  public void testAllowUrlProtocol1() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .toFactory();

    String aTagString = "<a href='http://example.com'>Hi</a>";
    String resultString = beforePolicy.sanitize(aTagString);
    assertEquals("Hi", resultString);

    PolicyFactory afterPolicy = beforePolicy.and(
            new HtmlPolicyBuilder()
                    .allowElements("a")
                    .allowAttributes("href")
                    .onElements("a")
                    .toFactory());

    resultString = afterPolicy.sanitize(aTagString);
    assertEquals("Hi", resultString);
  }

  // before : X
  // after : allow(http)
  @Test
  public void testAllowUrlProtocol2() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .toFactory();

    String aTagString = "<a href='http://example.com'>Hi</a>";
    String resultString = beforePolicy.sanitize(aTagString);
    assertEquals("Hi", resultString);

    PolicyFactory afterPolicy = beforePolicy.and(
            new HtmlPolicyBuilder()
                    .allowElements("a")
                    .allowAttributes("href")
                    .onElements("a")
                    .allowUrlProtocols("http")
                    .toFactory());

    // todo
    resultString = afterPolicy.sanitize(aTagString);
    assertEquals("<a href='http://example.com'>Hi</a>", resultString);
  }

  // before : X
  // after : disallow(http)
  @Test
  public void testAllowUrlProtocol3() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .toFactory();

    String aTagString = "<a href='http://example.com'>Hi</a>";
    String resultString = beforePolicy.sanitize(aTagString);
    assertEquals("Hi", resultString);

    PolicyFactory afterPolicy = beforePolicy.and(
            new HtmlPolicyBuilder()
                    .allowElements("a")
                    .allowAttributes("href")
                    .onElements("a")
                    .disallowUrlProtocols("http")
                    .toFactory());

    resultString = afterPolicy.sanitize(aTagString);
    assertEquals("Hi", resultString);
  }

  // before : allow(http)
  // after : X
  @Test
  public void testAllowUrlProtocol4() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .allowUrlProtocols("http")
            .toFactory();

    String aTagString = "<a href='http://example.com'>Hi</a>";
    String resultString = beforePolicy.sanitize(aTagString);
    assertEquals("<a href=\"http://example.com\">Hi</a>", resultString);

    PolicyFactory afterPolicy = beforePolicy.and(
            new HtmlPolicyBuilder()
                    .allowElements("a")
                    .allowAttributes("href")
                    .onElements("a")
                    .toFactory());

    // todo afterPolicy가 없을 때 이전 정책을 따라가야 하는지, 없는것도 정책 설정이라고 봐야할지
    resultString = afterPolicy.sanitize(aTagString);
    assertEquals("Hi", resultString);
  }

  // before : allow(http)
  // after : allow(http)
  @Test
  public void testAllowUrlProtocol5() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .allowUrlProtocols("http")
            .toFactory();

    String aTagString = "<a href='http://example.com'>Hi</a>";
    String resultString = beforePolicy.sanitize(aTagString);
    assertEquals("<a href=\"http://example.com\">Hi</a>", resultString);

    PolicyFactory afterPolicy = beforePolicy.and(
            new HtmlPolicyBuilder()
                    .allowElements("a")
                    .allowAttributes("href")
                    .onElements("a")
                    .allowUrlProtocols("http")
                    .toFactory());

    resultString = afterPolicy.sanitize(aTagString);
    assertEquals("<a href=\"http://example.com\">Hi</a>", resultString);
  }

  // before : allow(http)
  // after : disallow(http)
  @Test
  public void testAllowUrlProtocol6() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .allowUrlProtocols("http")
            .toFactory();

    String aTagString = "<a href='http://example.com'>Hi</a>";
    String resultString = beforePolicy.sanitize(aTagString);
    assertEquals("<a href=\"http://example.com\">Hi</a>", resultString);

    PolicyFactory afterPolicy = beforePolicy.and(
            new HtmlPolicyBuilder()
                    .allowElements("a")
                    .allowAttributes("href")
                    .onElements("a")
                    .disallowUrlProtocols("http")
                    .toFactory());

    resultString = afterPolicy.sanitize(aTagString);
    assertEquals("Hi", resultString);
  }

  // before : disallow(http)
  // after : X
  @Test
  public void testAllowUrlProtocol7() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .disallowUrlProtocols("http")
            .toFactory();

    String aTagString = "<a href='http://example.com'>Hi</a>";
    String resultString = beforePolicy.sanitize(aTagString);
    assertEquals("Hi", resultString);

    PolicyFactory afterPolicy = beforePolicy.and(
            new HtmlPolicyBuilder()
                    .allowElements("a")
                    .allowAttributes("href")
                    .onElements("a")
                    .toFactory());

    resultString = afterPolicy.sanitize(aTagString);
    assertEquals("Hi", resultString);
  }

  // before : disallow(http)
  // after : allow(http)
  @Test
  public void testAllowUrlProtocol8() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .disallowUrlProtocols("http")
            .toFactory();

    String aTagString = "<a href='http://example.com'>Hi</a>";
    String resultString = beforePolicy.sanitize(aTagString);
    assertEquals("Hi", resultString);

    PolicyFactory afterPolicy = beforePolicy.and(
            new HtmlPolicyBuilder()
                    .allowElements("a")
                    .allowAttributes("href")
                    .onElements("a")
                    .allowUrlProtocols("http")
                    .toFactory());

    // todo
    resultString = afterPolicy.sanitize(aTagString);
    assertEquals("<a href=\"http://example.com\">Hi</a>", resultString);
  }

  // before : disallow(http)
  // after : disallow(http)
  @Test
  public void testAllowUrlProtocol9() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
            .onElements("a")
            .disallowElements()
            .disallowUrlProtocols("http")
            .toFactory();

    String aTagString = "<a href='http://example.com'>Hi</a>";
    String resultString = beforePolicy.sanitize(aTagString);
    assertEquals("Hi", resultString);

    PolicyFactory afterPolicy = beforePolicy.and(
            new HtmlPolicyBuilder()
                    .allowElements("a")
                    .allowAttributes("href")
                    .onElements("a")
                    .disallowUrlProtocols("http")
                    .toFactory());

    // todo
    resultString = afterPolicy.sanitize(aTagString);
    assertEquals("Hi", resultString);
  }
}
