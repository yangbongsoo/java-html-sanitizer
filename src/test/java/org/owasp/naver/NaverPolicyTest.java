package org.owasp.naver;

import static org.junit.Assert.*;
import static org.owasp.naver.WhiteUrlUtils.*;

import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

import org.junit.Before;
import org.junit.Test;
import org.owasp.html.CssSchema;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.HtmlStreamEventProcessor;
import org.owasp.html.HtmlStreamEventReceiver;
import org.owasp.html.HtmlStreamEventReceiverWrapper;
import org.owasp.html.PolicyFactory;

import com.google.common.collect.ImmutableSet;
import junit.framework.TestCase;

public class NaverPolicyTest extends TestCase {

	@Before
	public void setUp() throws Exception {
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
								System.out.println("upper!!");
								underlying.text(s.toUpperCase());
							}
							@Override
							public String toString() {
								return "shouty-text";
							}
						}
				)
				.toFactory();

		String spanTagString = "<span>Hi</span>";
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

	@Test
	public void testAElement() {
		String dirty = "<p>"
				+ "<a href='java\0script:bad()'>1</a>"
				+ "<a style='color: red; font-weight; expression(foo());, direction: rtl; font-weight: bold'>2</a>"
				+ "<a href='foo.html'>3</a>"
				+ "<a href='http://outside.org/'>4</a>"
				+ "</p>";
		String clean = NaverPolicy.sanitize(dirty);
		assertEquals("<p><a>1</a><a>2</a><a href=\"foo.html\">3</a><a href=\"http://outside.org/\">4</a></p>", clean);
	}

	@Test
	public void testSpanTag() {
		String dirty = "<span><div><h1>Hello</h1></div></span>";
		String clean = NaverPolicy.sanitize(dirty);
		assertEquals("<span><div><h1>Hello</h1></div></span>", clean);
	}

	@Test
	public void testNoscriptTag() {
		String dirty = "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">";
		String clean = NaverPolicy.sanitize(dirty);
		System.out.println(clean);
		assertEquals("<noscript>"
				+ "<p title=\"&lt;/noscript&gt;&lt;img src&#61;x onerror&#61;alert(1)&gt;\">"
				+ "</p>"
				+ "</noscript>", clean);
	}

	@Test
	public void testImageTag() {
		String dirty = "<image src=\"http://example.com/foo.png\" />";
		String clean = NaverPolicy.sanitize(dirty);
		assertEquals("", clean);

		dirty = "<Image src=\"http://example.com/bar.png\"><IMAGE>";
		clean = NaverPolicy.sanitize(dirty);
		assertEquals("", clean);
	}

	@Test
	public void testKoreanTag() {
		String dirty = "<하하하>";
		String clean = NaverPolicy.sanitize(dirty);
		assertEquals("&lt;하하하&gt;", clean);
	}

	@Test
	public void testUrlEncodingData() {
		// before encoding
		String dirty = "http://m.id.hangame.com/searchInfo.nhn?type=FINDID&nxtURL=http://m.tera.hangame.com</script><img src=pooo.png onerror=alert(/V/)>";
		String clean = NaverPolicy.sanitize(dirty);
		assertEquals("http://m.id.hangame.com/searchInfo.nhn?type&#61;FINDID&amp;nxtURL&#61;http://m.tera.hangame.com<img src=\"pooo.png\" />", clean);

		// after encoding
		dirty = "http://m.id.hangame.com/searchInfo.nhn?type=FINDID&nxtURL=http://m.tera.hangame.com%3C/script%3E%3Cimg%20src=pooo.png%20onerror=alert(/V/)%3E";
		clean = NaverPolicy.sanitize(dirty);
		assertEquals("http://m.id.hangame.com/searchInfo.nhn?type&#61;FINDID&amp;nxtURL&#61;http://m.tera.hangame.com%3C/script%3E%3Cimg%20src&#61;pooo.png%20onerror&#61;alert(/V/)%3E", clean);
	}

	@Test
	public void testNotAllowedPatternSrcAttribute() {
		String dirty = "<img src='http://sstorym.cafe24.com/deScription/lereve/lelogo.gif' width='700'>";
		String clean = NaverPolicy.sanitize(dirty);
		assertEquals("<img src=\"http://sstorym.cafe24.com/deScription/lereve/lelogo.gif\" width=\"700\" />", clean);

		dirty = "<img src='scription/lereve/lelogo.gif' width='700'>";
		clean = NaverPolicy.sanitize(dirty);
		assertEquals("<img src=\"scription/lereve/lelogo.gif\" width=\"700\" />", clean);

		dirty = "<img src='script:/lereve/lelogo.gif' width='700'>";
		clean = NaverPolicy.sanitize(dirty);
		assertEquals("<img width=\"700\" />", clean);
	}

	@Test
	public void testAllowStylingCheckPoint() {
		String dirty = "<b style=font-size:larger></b>";
		String clean = NaverPolicy.sanitize(dirty);
		assertEquals("<b style=\"font-size:larger\"></b>", clean);

		//    ImmutableSet<String> fontLiterals1 = ImmutableSet.of(
		//        "large", "larger", "small", "smaller", "x-large", "x-small",
		//        "xx-large", "xx-small");

		dirty = "<b style=font-size:bigger></b>";
		clean = NaverPolicy.sanitize(dirty);
		assertEquals("<b></b>", clean);
	}

	@Test
	public void testHrefAttack() {
		// href는 FilterUrlByProtocolAttributePolicy 정책을 따른다. : 앞이 프로토콜로 인식하는데 가능한건 http, https 니까 제거됌
		String dirty = "<a HREF=\"javascript:alert('XSS');\">Hello</a>";
		String clean = NaverPolicy.sanitize(dirty);
		assertEquals("<a>Hello</a>", clean);
	}

	@Test
	public void testLinkElement() {
		String dirty = "<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">";
		String clean = NaverPolicy.sanitize(dirty);
		assertEquals("", clean);
	}

	@Test
	public void testStyleAttribute() {
		String dirty = "<DIV STYLE=\"color:red;background-image: url(javascript:alert('XSS'))\">"; // : 앞이 프로토콜로 인식하는데 가능한건 http, https 니까 제거됌
		String clean = NaverPolicy.sanitize(dirty);
		assertEquals("<div style=\"color:red\"></div>", clean);

		dirty = "<a href=\"../good.html\" rel=\"nofollow\" style=\"color:red\"></a>";
		clean = NaverPolicy.sanitize(dirty);
		assertEquals("<a href=\"../good.html\" rel=\"nofollow\"></a>", clean);

		dirty = "<marquee STYLE=\"color:red;background-image: url(javascript:alert('XSS'))\">";
		clean = NaverPolicy.sanitize(dirty);
		assertEquals("<marquee></marquee>", clean);
	}

	@Test
	public void testEmptyTag() {

		String dirty = "<a b>";
		String clean = NaverPolicy.sanitize(dirty);
		assertEquals("<a></a>", clean);

		dirty = "<!a>";
		clean = NaverPolicy.sanitize(dirty);
		assertEquals("", clean);

		dirty = "<p>";
		clean = NaverPolicy.sanitize(dirty);
		assertEquals("<p></p>", clean);

		dirty = "</p>";
		clean = NaverPolicy.sanitize(dirty);
		assertEquals("", clean);

		dirty = "<li></li>";
		clean = NaverPolicy.sanitize(dirty);
		assertEquals("<ul><li></li></ul>", clean);

		// TagBalancingHtmlStreamEventReceiver.java 111 Line 에서 tbody 추가
		dirty = "<table><td>Hello</td></table>";
		clean = NaverPolicy.sanitize(dirty);
		assertEquals("<table><tbody><tr><td>Hello</td></tr></tbody></table>", clean);

		dirty = "<colgroup width=\"";
		clean = NaverPolicy.sanitize(dirty);
		assertEquals("<table><colgroup></colgroup></table>", clean);
	}

	@Test
	public void testVideoElement() {
		String dirty = "<video width=\"320\" height=\"240\" controls=\"controls\"><source src=\"movie.mp4\" type=\"video/mp4\" pubdate=\"\"></video>";
		String clean = NaverPolicy.sanitize(dirty);
		assertEquals("<video width=\"320\" height=\"240\" controls=\"controls\"><source src=\"movie.mp4\" type=\"video/mp4\" /></video>", clean);
	}

	@Test
	public void testAttributeComment() {
		String dirty = "<p tt='-->'>Hello</p>";
		String clean = NaverPolicy.sanitize(dirty);
		assertEquals("<p>Hello</p>", clean);
	}
}
