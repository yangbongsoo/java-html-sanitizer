package org.owasp.html;

import static org.junit.Assert.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.owasp.naver.NaverHtmlPolicy;

import com.google.common.base.Charsets;
import com.google.common.io.Resources;

public class NaverPolicyTest {

	private static final String[] NORMAL_HTML_FILES = {"xss-normal1.html"};

	@Before
	public void setUp() throws Exception {
	}

	@Test
	public void aElementTest() {
		String dirty1 = "<p>"
			+ "<a href='java\0script:bad()'>1</a>"
			+ "<a style='color: red; font-weight; expression(foo());, direction: rtl; font-weight: bold'>2</a>"
			+ "<a href='foo.html'>3</a>"
			+ "<a href='http://outside.org/'>4</a>"
			+ "</p>";
		String clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty1);
		assertEquals("<p><a>1</a><a>2</a><a href=\"foo.html\">3</a><a href=\"http://outside.org/\">4</a></p>", clean);
	}

	@Test
	public void expandTest() {
	// todo extend test
		PolicyFactory expandPolicy = NaverHtmlPolicy.getExpandPolicy(
			new HtmlPolicyBuilder()
				.allowElements("a")
				.allowAttributes("style").onElements("a")
				.toFactory());

//		getExpandPolicy.sanitize()
	}

	@Test
	public void name() {
		String dirty = "<a>Y</a>";
		String clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		System.out.println(clean);
	}

	@Test
	public void spanTagTest() {
		String dirty = "<span><div><h1>Hello</h1></div></span>";
		String clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		assertEquals("<span><div><h1>Hello</h1></div></span>", clean);
		System.out.println(clean);
	}

	@Test
	public void noscriptTagTest() {
		String dirty = "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">";
		String clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		System.out.println(clean);
		assertEquals("<noscript>"
				+ "<p title=\"&lt;/noscript&gt;&lt;img src&#61;x onerror&#61;alert(1)&gt;\">"
				+ "</p>"
				+ "</noscript>", clean);
	}

	@Test
	public void imageTagTest() {
//		String dirty = "<a href='javascript:alert(1337)//:http'>Bad</a>";
		String dirty = "<image src=\"http://example.com/foo.png\" />";
		String clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		assertEquals("<img src=\"http://example.com/foo.png\" />", clean);

		dirty = "<Image src=\"http://example.com/bar.png\"><IMAGE>";
		clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		assertEquals("<img src=\"http://example.com/bar.png\" /><img />", clean);
	}

	// todo only string
	@Test
	public void onlyStringTest() {
		String dirty = "javascript:alert(1)";
		String clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		System.out.println(clean);
	}

	@Test
	public void koreanTagTest() {
		String dirty = "<하하하>";
		String clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		assertEquals("&lt;하하하&gt;", clean);

	}

	@Test
	public void urlEncodingData() {
		// before encoding
		String dirty = "http://m.id.hangame.com/searchInfo.nhn?type=FINDID&nxtURL=http://m.tera.hangame.com</script><img src=pooo.png onerror=alert(/V/)>";
		String clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		assertEquals("http://m.id.hangame.com/searchInfo.nhn?type&#61;FINDID&amp;nxtURL&#61;http://m.tera.hangame.com<img src=\"pooo.png\" />", clean);

		// after encoding
		dirty = "http://m.id.hangame.com/searchInfo.nhn?type=FINDID&nxtURL=http://m.tera.hangame.com%3C/script%3E%3Cimg%20src=pooo.png%20onerror=alert(/V/)%3E";
		clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		assertEquals("http://m.id.hangame.com/searchInfo.nhn?type&#61;FINDID&amp;nxtURL&#61;http://m.tera.hangame.com%3C/script%3E%3Cimg%20src&#61;pooo.png%20onerror&#61;alert(/V/)%3E", clean);
	}

	@Test
	public void notAllowedPatternSrcAttribute() {
		String dirty = "<img src='http://sstorym.cafe24.com/deScription/lereve/lelogo.gif' width='700'>";
		String clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		assertEquals("<img src=\"http://sstorym.cafe24.com/deScription/lereve/lelogo.gif\" width=\"700\" />", clean);

		dirty = "<img src='scription/lereve/lelogo.gif' width='700'>";
		clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		assertEquals("<img src=\"scription/lereve/lelogo.gif\" width=\"700\" />", clean);

		dirty = "<img src='script:/lereve/lelogo.gif' width='700'>";
		clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		assertEquals("<img width=\"700\" />", clean);
	}

	@Test
	public void allowStylingCheckPoint() {
		String dirty = "<b style=font-size:larger></b>";
		String clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		assertEquals("<b style=\"font-size:larger\"></b>", clean);

		//    ImmutableSet<String> fontLiterals1 = ImmutableSet.of(
		//        "large", "larger", "small", "smaller", "x-large", "x-small",
		//        "xx-large", "xx-small");

		dirty = "<b style=font-size:bigger></b>";
		clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		assertEquals("<b></b>", clean);
	}

	@Test
	public void hrefAttackTest() {
		// href는 FilterUrlByProtocolAttributePolicy 정책을 따른다. : 앞이 프로토콜로 인식하는데 가능한건 http, https 니까 제거됌
		String dirty = "<a HREF=\"javascript:alert('XSS');\">Hello</a>";
		String clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		assertEquals("<a>Hello</a>", clean);
	}

	@Test
	public void linkElementTest() {
		String dirty = "<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">";
		String clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		assertEquals("", clean);
	}

	@Test
	public void styleAttributeTest() {
		String dirty = "<DIV STYLE=\"color:red;background-image: url(javascript:alert('XSS'))\">"; // : 앞이 프로토콜로 인식하는데 가능한건 http, https 니까 제거됌
		String clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		assertEquals("<div style=\"color:red\"></div>", clean);

		dirty = "<a href=\"../good.html\" rel=\"nofollow\" style=\"color:red\"></a>";
		clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		assertEquals("<a href=\"../good.html\" rel=\"nofollow\"></a>", clean);

		dirty = "<marquee STYLE=\"color:red;background-image: url(javascript:alert('XSS'))\">";
		clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		assertEquals("<marquee></marquee>", clean);
	}

	@Test
	public void emptyTagTest() {

		String dirty = "<a b>";
		String clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		assertEquals("<a></a>", clean);

		dirty = "<!a>";
		clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		assertEquals("", clean);

		dirty = "<p>";
		clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		assertEquals("<p></p>", clean);

		dirty = "</p>";
		clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		assertEquals("", clean);

		dirty = "<li></li>";
		clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		assertEquals("<ul><li></li></ul>", clean);

		// TagBalancingHtmlStreamEventReceiver.java 111 Line 에서 tbody 추가
		dirty = "<table><td>Hello</td></table>";
		clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		assertEquals("<table><tbody><tr><td>Hello</td></tr></tbody></table>", clean);

		dirty = "<colgroup width=\"";
		clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		assertEquals("<table><colgroup></colgroup></table>", clean);
	}

	@Test
	public void videoElementTest() {
		String dirty = "<video width=\"320\" height=\"240\" controls=\"controls\"><source src=\"movie.mp4\" type=\"video/mp4\" pubdate=\"\"></video>";
		String clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		assertEquals("<video width=\"320\" height=\"240\" controls=\"controls\"><source src=\"movie.mp4\" type=\"video/mp4\" /></video>", clean);
	}

	@Test
	public void attributeCommentTest() {
		String dirty = "<p tt='-->'>Hello</p>";
		String clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		assertEquals("<p>Hello</p>", clean);
	}
}
