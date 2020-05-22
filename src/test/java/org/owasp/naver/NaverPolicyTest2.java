package org.owasp.naver;

import static org.owasp.naver.WhiteUrlUtils.*;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import org.junit.Before;
import org.junit.Test;
import org.owasp.html.CssSchema;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.HtmlStreamEventReceiverWrapper;
import org.owasp.html.PolicyFactory;

import com.google.common.collect.ImmutableSet;
import junit.framework.TestCase;

public class NaverPolicyTest2 extends TestCase {

	/**
	 * original source : https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
	 *
	 */

	@Test
	public void testRestrictedCharacters() {
		List<String> attackStringList = Arrays.asList(
				"<script>onerror=alert;throw 1</script>",
				"<script>{onerror=alert}throw 1</script>",
				"<script>throw onerror=alert,1</script>",
				"<script>throw onerror=eval,'=alert\\x281\\x29'</script>",
				"<script>{onerror=eval}throw{lineNumber:1,columnNumber:1,fileName:1,message:'alert\\x281\\x29'}</script>",
				"<script>'alert\\x281\\x29'instanceof{[Symbol.hasInstance]:eval}</script>",
				"<script>'alert\\x281\\x29'instanceof{[Symbol['hasInstance']]:eval}</script>",
				"<script>location='javascript:alert\\x281\\x29'</script>",
				"<script>location=name</script>",
				"<script>alert`1`</script>",
				"<script>new Function`X${document.location.hash.substr`1`}`</script>",
				"<script>Function`X${document.location.hash.substr`1`}```</script>"
		);

		for (String eachAttackString : attackStringList) {
			assertEquals("", NaverPolicy.sanitize(eachAttackString));
		}
	}

	@Test
	public void testFrameworks() {
		List<String> attackStringList = Arrays.asList(
			"<xss class=progress-bar-animated onanimationstart=alert(1)>",
			"<xss class=\"carousel slide\" data-ride=carousel data-interval=100 ontransitionend=alert(1)><xss class=carousel-inner><xss class=\"carousel-item active\"></xss><xss class=carousel-item></xss></xss></xss>"
		);

		for (String eachAttackString : attackStringList) {
			assertEquals("", NaverPolicy.sanitize(eachAttackString));
		}
	}

	@Test
	public void testProtocols() {
		String attackString = "<iframe src=\"javascript:alert(1)\">";
		String cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("", cleanString);

		attackString = "<object data=\"javascript:alert(1)\">";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("", cleanString);


		attackString = "<embed src=\"javascript:alert(1)\">";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("", cleanString);

		attackString = "<a href=\"javascript:alert(1)\">XSS</a>";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("<a>XSS</a>", cleanString);

		attackString = "<a href=\"JaVaScript:alert(1)\">XSS</a>";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("<a>XSS</a>", cleanString);

		attackString = "<a href=\" \tjavascript:alert(1)\">XSS</a>";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("<a>XSS</a>", cleanString);

		attackString = "<a href=\"javas\tcript:alert(1)\">XSS</a>";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("<a>XSS</a>", cleanString);

		attackString = "<a href=\"javascript\n"
				+ ":alert(1)\">XSS</a>";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("<a>XSS</a>", cleanString);

		attackString = "<svg><a xlink:href=\"javascript:alert(1)\"><text x=\"20\" y=\"20\">XSS</text></a>";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("<a>XSS</a>", cleanString);

		attackString = "<svg><animate xlink:href=#xss attributeName=href values=javascript:alert(1) /><a id=xss><text x=20 y=20>XSS</text></a>";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("<a id=\"xss\">XSS</a>", cleanString);

		attackString = "<svg><animate xlink:href=#xss attributeName=href from=javascript:alert(1) to=1 /><a id=xss><text x=20 y=20>XSS</text></a>";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("<a id=\"xss\">XSS</a>", cleanString);

		attackString = "<svg><set xlink:href=#xss attributeName=href from=? to=javascript:alert(1) /><a id=xss><text x=20 y=20>XSS</text></a>";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("<a id=\"xss\">XSS</a>", cleanString);

		attackString = "<script src=\"data:text/javascript,alert(1)\"></script>";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("", cleanString);

		attackString = "<svg><script href=\"data:text/javascript,alert(1)\" />";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("", cleanString);

		attackString = "<svg><use href=\"data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink' width='100' height='100'><a xlink:href='javascript:alert(1)'><rect x='0' y='0' width='100' height='100' /></a></svg>#x\"></use></svg>";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("", cleanString);

		attackString = "<script>import('data:text/javascript,alert(1)')</script>";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("", cleanString);

		attackString = "<base href=\"javascript:/a/-alert(1)///////\"><a href=../lol/safari.html>test</a>";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("<a href=\"../lol/safari.html\">test</a>", cleanString);

		attackString = "<math><x href=\"javascript:alert(1)\">blah";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("blah", cleanString);

		attackString = "<form><button formaction=javascript:alert(1)>XSS";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("<form><button>XSS</button></form>", cleanString);

		attackString = "<form><input type=submit formaction=javascript:alert(1) value=XSS>";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("<form><input type=\"submit\" value=\"XSS\" /></form>", cleanString);

		attackString = "<form action=javascript:alert(1)><input type=submit value=XSS>";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("<form><input type=\"submit\" value=\"XSS\" /></form>", cleanString);

		attackString = "<isindex type=submit formaction=javascript:alert(1)>";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("", cleanString);

		attackString = "<isindex type=submit action=javascript:alert(1)>";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("", cleanString);

		attackString = "<svg><use href=\"//subdomain1.portswigger-labs.net/use_element/upload.php#x\" /></svg>";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("", cleanString);

		attackString = "<svg><animate xlink:href=#xss attributeName=href dur=5s repeatCount=indefinite keytimes=0;0;1 values=\"https://portswigger.net?&semi;javascript:alert(1)&semi;0\" /><a id=xss><text x=20 y=20>XSS</text></a>";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("<a id=\"xss\">XSS</a>", cleanString);
	}

	@Test
	public void testOtherUsefulAttributes() {
		String attackString = "<iframe srcdoc=\"<img src=1 onerror=alert(1)>\"></iframe>";
		String cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("", cleanString);

		attackString = "<iframe srcdoc=\"&lt;img src=1 onerror=alert(1)&gt;\"></iframe>";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("", cleanString);

		attackString = "<form action=\"javascript:alert(1)\"><input type=submit id=x></form><label for=x>XSS</label>";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("<form><input type=\"submit\" id=\"x\" /></form><label for=\"x\">XSS</label>", cleanString);

		attackString = "<input type=\"hidden\" accesskey=\"X\" onclick=\"alert(1)\"> (Press ALT+SHIFT+X on Windows) (CTRL+ALT+X on OS X)";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("<input type=\"hidden\" accesskey=\"X\" /> (Press ALT&#43;SHIFT&#43;X on Windows) (CTRL&#43;ALT&#43;X on OS X)", cleanString);

		attackString = "<link rel=\"canonical\" accesskey=\"X\" onclick=\"alert(1)\" /> (Press ALT+SHIFT+X on Windows) (CTRL+ALT+X on OS X)";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals(" (Press ALT&#43;SHIFT&#43;X on Windows) (CTRL&#43;ALT&#43;X on OS X)", cleanString);

		attackString = "<a href=# download=\"filename.html\">Test</a>";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("<a href=\"#\">Test</a>", cleanString);

		attackString = "<img referrerpolicy=\"no-referrer\" src=\"//portswigger-labs.net\">";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("<img src=\"//portswigger-labs.net\" />", cleanString);

		attackString = "<a href=# onclick=\"window.open('http://subdomain1.portswigger-labs.net/xss/xss.php?context=js_string_single&x=%27;eval(name)//','alert(1)')\">XSS</a>";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("<a href=\"#\">XSS</a>", cleanString);

		attackString = "<iframe name=\"alert(1)\" src=\"https://portswigger-labs.net/xss/xss.php?context=js_string_single&x=%27;eval(name)//\"></iframe>";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("", cleanString);

		attackString = "<base target=\"alert(1)\"><a href=\"http://subdomain1.portswigger-labs.net/xss/xss.php?context=js_string_single&x=%27;eval(name)//\">XSS via target in base tag</a>";
		cleanString = NaverPolicy.sanitize(attackString);
		assertEquals("<a href=\"http://subdomain1.portswigger-labs.net/xss/xss.php?context&#61;js_string_single&amp;x&#61;%27;eval%28name%29//\">XSS via target in base tag</a>", cleanString);

		// Set window.name via target attribute in a <a> tag
		attackString = "<a target=\"alert(1)\" href=\"http://subdomain1.portswigger-labs.net/xss/xss.php?context=js_string_single&x=%27;eval(name)//\">XSS via target in a tag</a>";
		cleanString = NaverPolicy.sanitize(attackString);
		// todo check
		assertEquals("<a target=\"alert(1)\" href=\"http://subdomain1.portswigger-labs.net/xss/xss.php?context&#61;js_string_single&amp;x&#61;%27;eval%28name%29//\" rel=\"noopener noreferrer\">XSS via target in a tag</a>", cleanString);

		// Set window.name via usemap attribute in a <img> tag
		attackString = "<img src=\"validimage.png\" width=\"10\" height=\"10\" usemap=\"#xss\"><map name=\"xss\"><area shape=\"rect\" coords=\"0,0,82,126\" target=\"alert(1)\" href=\"http://subdomain1.portswigger-labs.net/xss/xss.php?context=js_string_single&x=%27;eval(name)//\"></map>";
		cleanString = NaverPolicy.sanitize(attackString);
		// todo check
		assertEquals("<img src=\"validimage.png\" width=\"10\" height=\"10\" usemap=\"#xss\" /><map name=\"xss\"><area shape=\"rect\" coords=\"0,0,82,126\" target=\"alert(1)\" href=\"http://subdomain1.portswigger-labs.net/xss/xss.php?context&#61;js_string_single&amp;x&#61;%27;eval%28name%29//\" /></map>", cleanString);

		// Set window.name via target attribute in a <form> tag
		attackString = "<form action=\"http://subdomain1.portswigger-labs.net/xss/xss.php\" target=\"alert(1)\"><input type=hidden name=x value=\"';eval(name)//\"><input type=hidden name=context value=js_string_single><input type=\"submit\" value=\"XSS via target in a form\"></form>";
		cleanString = NaverPolicy.sanitize(attackString);
		// todo check
		assertEquals("<form action=\"http://subdomain1.portswigger-labs.net/xss/xss.php\" target=\"alert(1)\"><input type=\"hidden\" name=\"x\" value=\"&#39;;eval(name)//\" /><input type=\"hidden\" name=\"context\" value=\"js_string_single\" /><input type=\"submit\" value=\"XSS via target in a form\" /></form>", cleanString);

		// Set window.name via formtarget attribute in a <input> tag type submit
		attackString = "<form><input type=hidden name=x value=\"';eval(name)//\"><input type=hidden name=context value=js_string_single><input type=\"submit\" formaction=\"http://subdomain1.portswigger-labs.net/xss/xss.php\" formtarget=\"alert(1)\" value=\"XSS via formtarget in input type submit\"></form>";
		cleanString = NaverPolicy.sanitize(attackString);
		// todo check
		assertEquals("<form><input type=\"hidden\" name=\"x\" value=\"&#39;;eval(name)//\" /><input type=\"hidden\" name=\"context\" value=\"js_string_single\" /><input type=\"submit\" formtarget=\"alert(1)\" value=\"XSS via formtarget in input type submit\" /></form>", cleanString);

		// Set window.name via formtarget attribute in a <input> tag type image
		attackString = "<form><input type=hidden name=x value=\"';eval(name)//\"><input type=hidden name=context value=js_string_single><input name=1 type=\"image\" src=\"validimage.png\" formaction=\"http://subdomain1.portswigger-labs.net/xss/xss.php\" formtarget=\"alert(1)\" value=\"XSS via formtarget in input type image\"></form>";
		cleanString = NaverPolicy.sanitize(attackString);
		// todo check
		assertEquals("<form><input type=\"hidden\" name=\"x\" value=\"&#39;;eval(name)//\" /><input type=\"hidden\" name=\"context\" value=\"js_string_single\" /><input name=\"1\" type=\"image\" src=\"validimage.png\" formtarget=\"alert(1)\" value=\"XSS via formtarget in input type image\" /></form>", cleanString);

	}

	// todo special tags
}
