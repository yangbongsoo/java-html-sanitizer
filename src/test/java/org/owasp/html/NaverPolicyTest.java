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


		// todo find the way how to make policy override easy
//		OVERRIDED_POLICY_DEFINITION = NAVER_DEFAULT_POLICY.and(
//			new HtmlPolicyBuilder()
//				.allowElements("a")
//				.allowAttributes(aAttributeArray).onElements("a")
//				.toFactory());
	}

	@Test
	public void aElementTest() {
		String dirty1 = "<p>"
			+ "<a href='java\0script:bad()'>1</a>"
			+ "<a style='color: red; font-weight; expression(foo());, direction: rtl; font-weight: bold'>2</a>"
			+ "<a href='foo.html'>3</a>"
			+ "<a href='http://outside.org/'>5</a>"
			+ "</p>";
		String clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty1);
		System.out.println(clean);
	}

	@Test
	public void expandTest() {
	// todo 기능 확장했을 때 정상적으로 extends 되는지 체크
		PolicyFactory expandPolicy = NaverHtmlPolicy.getExpandPolicy(
			new HtmlPolicyBuilder()
				.allowElements("a")
				.allowAttributes("style").onElements("a")
				.toFactory());

//		getExpandPolicy.sanitize()
	}

	@Test
	public void span() {
//		String dirty = "<a b>";
//		String dirty = "<!a>"; // 요놈은 태그(엘리먼트)로 인식하면 안된다.
//		String dirty = " onmouseover=prompt(954996)";
//		String dirty = "<span><div><h1>div테스트</h1></div></span>";
//		String dirty = "<div><span><h1>div테스트</h1></span></div>";
//		String dirty = "<div><span><p>div테스트</p></span></div>";

		// todo span 에 속성이 없으면 span 태그 자체가 없어지는 이유가 뭘까
//		String dirty = "<span style=\"color:red\">ABC</span>";
		String dirty = "<span>ABC</span>";
//		String dirty = "<b>ABC</b>";

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
		String dirty = "<a HREF=\"javascript:alert('XSS');\">Hello</a>"; // href는 FilterUrlByProtocolAttributePolicy 정책을 따른다. : 앞이 프로토콜로 인식하는데 가능한건 http, https 니까 제거됌
		String clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		assertEquals("Hello", clean);
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
	public void abb() {
		// todo how to check style not allowed pattern? Is it impossible?
		/*
		<attribute name="style">
			<notAllowedPattern><![CDATA[(?i:j\\*a\\*v\\*a\\*s\\*c\\*r\\*i\\*p\\*t\\*:)]]></notAllowedPattern>
			<notAllowedPattern><![CDATA[(?i:e\\*x\\*p\\*r\\*e\\*s\\*s\\*i\\*o\\*n)]]></notAllowedPattern>
			<notAllowedPattern><![CDATA[&[#\\%x]+[\da-fA-F][\da-fA-F]+]]></notAllowedPattern>
		</attribute>
		*/
//		String dirty = "<div style=\"color:red;background-image: url(alert('XSS'))\">";
//		String dirty = "<DIV STYLE=\"background-image: TEST\">";
//		String dirty = "<DIV STYLE=\"color: red\">";
//		String dirty = "<div style=\"color:red;background-image:url(&#39;http://example.com/foo.png&#39;)\">div content</div>";
//		String dirty = "<div style=\"background-image: url(\'test.png\')\">Hello</div>";
//		String dirty = "<div style=\"background-image: url(\'images/test.png\')\">Hello</div>";
//		String dirty = "<div style=\"background-image: url(\"images/test.png\")\">Hello</div>";
//		String dirty = "<div style=\"background-image: none\">div content</div>";
//		String clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
//		assertEquals("<table><colgroup></colgroup></table>", clean);
		String dirty = "<img src='script:/lereve/lelogo.gif' width='700'>";
		String clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		System.out.println(clean);
	}

	@Test
	public void emptyTagTest() {
		String dirty = "<p>";
		String clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		assertEquals("<p></p>", clean);

		dirty = "</p>";
		clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
		assertEquals("", clean);

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

//	@Test
//	public void objectTest() throws Exception {
//		String dirty = "<object type=\"text/html\"><param name=\"src\" value=\"http://serviceapi.nmv.naver.com/\"></object>";
//		String clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(dirty);
//		System.out.println(clean);
//	}

//	@Test
//	// 정상적인 HTML 페이지를 통과 시키는지 검사한다.(필터링 전후가 동일하면 정상)
//	public void testHtmlFiltering() throws Exception {
//		for (String valid : readString(NORMAL_HTML_FILES)) {
//			String clean = NaverHtmlPolicy.getDefaultPolicy().sanitize(valid);
//			assertEquals("\n" + valid + "\n" + clean, valid, clean);
//		}
//	}
//
//	protected List<String> readString(String... filePaths) throws Exception {
//		List<String> result = new ArrayList<>();
//		for (String filePath : filePaths) {
//			result.add(readString(filePath));
//		}
//		return result;
//	}
//
//	protected String readString(String filePath) throws IOException {
//		List<String> lines = readLines(filePath);
//		StringBuilder buffer = new StringBuilder();
//		for (String line : lines) {
//			buffer.append(line);
//		}
//
//		return buffer.toString();
//	}
//
//	// 클래스 경로의 파일을 읽고 라인 단위로 읽어서() List로 반환한다.
//	protected List<String> readLines(String filePath) throws IOException {
//		List<String> lines = new ArrayList<>();
//		InputStream resourceAsStream = this.getClass().getResourceAsStream(filePath);
//		BufferedReader in = new BufferedReader(new InputStreamReader(
//				resourceAsStream, StandardCharsets.UTF_8));
//		String line;
//		while (null != (line = in.readLine())) {
//			if (line.startsWith("#") || 0 == line.length()) {
//				continue;
//			}
//
//			lines.add(line.trim());
//		}
//		in.close();
//
//		return lines;
//	}
}
