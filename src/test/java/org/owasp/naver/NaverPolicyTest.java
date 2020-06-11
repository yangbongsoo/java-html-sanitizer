package org.owasp.naver;

import com.google.common.collect.ImmutableSet;
import junit.framework.TestCase;
import org.junit.Before;
import org.junit.Test;
import org.owasp.html.*;

import java.util.List;
import java.util.regex.Pattern;

import static org.owasp.naver.WhiteUrlUtils.convertToPatternList;

public class NaverPolicyTest extends TestCase {

  @Before
  public void setUp() throws Exception {
  }

  @Test
  public void testName() {
    PolicyFactory expandPolicy = NaverPolicy.getExpandPolicy(
            new HtmlPolicyBuilder()
                    .allowElements("img")
                    .allowAttributes("nhn_extra_image")
                    .matching(Pattern.compile("[a-zA-Z'\"]+"))
                    .onElements("img")
                    .toFactory());

    String output = expandPolicy.sanitize("<img src=\"example.com\" nhn_extra_image=abc />");
    System.out.println(output);
  }

  @Test
  public void testExpandWhiteUrl() {

    List<Pattern> patternList = convertToPatternList(WhiteUrlSample.A_HREF_WHITE_URL_LIST);

    PolicyFactory expandPolicy = NaverPolicy.getExpandPolicy(
            new HtmlPolicyBuilder()
                    .allowElements("a")
                    .allowAttributes("href").matching(
                    WhiteUrlUtils.predicate(patternList)
            ).onElements("a")
                    .allowUrlProtocols("https", "http")
                    .toFactory());

//		String dirty = "<a href='http://outside.org/'>4</a>";
    String dirty = "<a href='http://serviceapi.nmv.naver.com/'></a>";
    String clean = expandPolicy.sanitize(dirty);
    System.out.println(clean);
  }

  @Test
  public void testExpand() {
    PolicyFactory policy = NaverPolicy.getExpandPolicy(NaverExtendPolicy.getExtendFactory());

    String dirty = "<span id=\"ss\" se2_tmp_te_border_style=\"custom\" style='position: absolute; bottom: inherit'></span>";
    String clean = policy.sanitize(dirty);
    System.out.println(clean);
  }

  @Test
  public void testStyleExtend() {
    ImmutableSet<String> EXTEND_WHITELIST = ImmutableSet.of("bottom", "position");
    CssSchema cssSchema = CssSchema.withProperties(EXTEND_WHITELIST);

    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("span")
            .allowStyling(cssSchema)
            .toFactory();

    String dirty = "<span id=\"ss\" se2_tmp_te_border_style=\"custom\" style='background-color: red;position: absolute; bottom: inherit'></span>";
    String clean = beforePolicy.sanitize(dirty);
    System.out.println(clean);

    ImmutableSet<String> EXTEND_WHITELIST2 = ImmutableSet.of("background-color");
    CssSchema cssSchema2 = CssSchema.withProperties(EXTEND_WHITELIST2);


    PolicyFactory afterPolicy = beforePolicy.and(new HtmlPolicyBuilder()
            .allowElements("span")
            .allowStyling(cssSchema2)
            .toFactory());

    clean = afterPolicy.sanitize(dirty);
    System.out.println(clean);

  }

  @Test
  public void testaa() {
    CssSchema.main();

    //		String dirty = "<a>Y</a>";
//		String clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
//		System.out.println(clean);
  }


  @Test
  public void testExpandLogic1() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href").onElements("a")
            .disallowAttributes("style").onElements("a")
            .allowUrlProtocols("https", "http")
            .toFactory();

    String dirty = "<a href='https://outside.org/' id=\"a-id\" style=\"color: red\">Hi</a>";
    String clean = beforePolicy.sanitize(dirty);
    assertEquals("<a href=\"https://outside.org/\">Hi</a>", clean);

    List<Pattern> patternList = convertToPatternList(WhiteUrlSample.A_HREF_WHITE_URL_LIST);

    PolicyFactory afterPolicy = beforePolicy.and(new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("id", "style").onElements("a")
            .allowAttributes("href").matching(WhiteUrlUtils.predicate(patternList)).onElements("a")
            .allowUrlProtocols("mailto")
            .toFactory());

    clean = afterPolicy.sanitize(dirty);
    assertEquals("<a id=\"a-id\" style=\"color: red\">Hi</a>", clean);
    System.out.println(clean);
  }

  // todo pre/post processor and logic
  @Test
  public void testExpandLogic2() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("span")
            .allowWithoutAttributes("span")
            .withPreprocessor(
                    r -> new HtmlStreamEventReceiverWrapper(r) {
                      @Override
                      public void text(String s) {
                        System.out.println("1. withPreprocessor-upper!! : " + s);
                        underlying.text(s.toUpperCase());
                      }
                    }
            )
            .withPostprocessor(
                    r -> new HtmlStreamEventReceiverWrapper(r) {
                      @Override
                      public void text(String s) {
                        System.out.println("2. withPostprocessor : " + s);
                        underlying.text(s);
                      }
                    }
            )
            .toFactory();

    String spanTagString = "<span>hi</span>";
    String resultString = beforePolicy.sanitize(spanTagString);
    assertEquals("<span>HI</span>", resultString);

    PolicyFactory afterPolicy = beforePolicy.and(NaverExtendPolicy.getExtendFactory());

    resultString = afterPolicy.sanitize(spanTagString);
    assertEquals("<span>hi</span>", resultString);
  }

  @Test
  public void testExpandLogic2_1() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("span")
            .toFactory();

    String spanTagString = "<span>Hi</span>";
    String resultString = beforePolicy.sanitize(spanTagString);
    assertEquals("Hi", resultString);

    PolicyFactory afterPolicy = beforePolicy.and(new HtmlPolicyBuilder()
            .allowElements("span")
            .allowWithoutAttributes("span")
            .toFactory());

    resultString = afterPolicy.sanitize(spanTagString);
    assertEquals("<span>Hi</span>", resultString);
  }

  @Test
  public void testExpandLogic3() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("span")
            .allowAttributes("id").onElements("span")
            .toFactory();

    String dirty = "<span id=\"span-id\" title=\"span-title\" style='color: red>Hi</span>";
    String clean = beforePolicy.sanitize(dirty);
    System.out.println(clean);

    PolicyFactory afterPolicy = beforePolicy.and(new HtmlPolicyBuilder()
            .allowElements("span")
            .allowAttributes("title").onElements("span")
            .toFactory());

    clean = afterPolicy.sanitize(dirty);
    System.out.println(clean);
  }

  // todo logic check
  public void testconfirmLogic() {
    // svg O
    // style O
    // script 는 text를 그냥 짤라버리네
    // rtc
    String input = "<rtc>Hi</rtc>";
    PolicyFactory expandPolicy = NaverPolicy.getExpandPolicy(
            new HtmlPolicyBuilder()
                    .allowElements("rtc")
//                    .allowAttributes("href").matching(
//                    WhiteUrlUtils.predicate(patternList)
//            ).onElements("a")
//                    .allowUrlProtocols("https", "http")
                    .toFactory());
    System.out.println(expandPolicy.sanitize(input));
  }

  public void testBaseLogic() {
//		String attackString = "<a href=\"//evil/\"";
//		String attackString = "<base href=\"//evil/\"";
    String attackString = "<area href=\"//evil/\"";
    String cleanString = NaverPolicy.sanitize(attackString);
    assertEquals("", cleanString);

  }

}
