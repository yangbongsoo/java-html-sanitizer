package org.owasp.html;

import org.junit.Before;
import org.junit.Test;
import org.owasp.naver.NaverHtmlPolicy;

public class NaverPolicyTest {

	@Before
	public void setUp() throws Exception {


		/* todo how to make notAllowedPattern rules
		<attribute name="href">
			<notAllowedPattern><![CDATA[(?i:j\\*a\\*v\\*a\\*s\\*c\\*r\\*i\\*p\\*t\\*:)]]></notAllowedPattern>
			<notAllowedPattern><![CDATA[&[#\\%x]+[\da-fA-F][\da-fA-F]+]]></notAllowedPattern>
		</attribute>
		*/

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
		PolicyFactory expandPolicy = NaverHtmlPolicy.getExpandPolicy(
			new HtmlPolicyBuilder()
				.allowElements("a")
				.allowAttributes("style").onElements("a")
				.toFactory());

//		getExpandPolicy.sanitize()
	}

	private static String[] addAll(String[] array1, String[] array2) {
		String[] tempArr = new String[array1.length + array2.length];
		System.arraycopy(array1, 0, tempArr, 0, array1.length);
		System.arraycopy(array2, 0, tempArr, array1.length, array2.length);
		return tempArr;
	}

}
