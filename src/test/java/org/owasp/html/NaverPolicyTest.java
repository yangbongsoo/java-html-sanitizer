package org.owasp.html;

import org.junit.Before;
import org.junit.Test;

public class NaverPolicyTest {
	// exclude attribute : translate, contenteditable, data-*, draggable, dropzone, spellcheck
	public String[] w3schoolsGlobalAttributeArray = {"accesskey", "class", "dir", "hidden", "id", "lang", "tabindex", "title", "style"};

	// exclude attribute : autocapitalize contenteditable contextmenu data-* draggable dropzone inputmode is itemid itemprop itemref itemscope itemtype part slot spellcheck translate
	public String[] mdnGlobalAttributeArray = {"accesskey", "class", "dir", "exportparts", "hidden", "id", "lang", "style", "tabindex", "title"};
	public String[] aDefaultAttributeArray = {"charset", "coords", "href", "hreflang", "media", "name", "rel", "rev", "shape", "target", "type"};
	public String[] appletDefaultAttributeArray = {"code", "object", "align", "alt", "archive", "codebase", "height", "hspace", "name", "vspace", "width"};

	// exclude attribute : download
	public String[] areaDefaultAttributeArray = {"alt", "coords", "href", "hreflang", "media", "nohref", "rel", "shape", "target", "type"};
	public String[] audioDefaultAttributeArray = {"autoplay", "controls", "loop", "muted", "preload", "src"};
	public String[] basefontDefaultAttributeArray = {"color", "face", "size"};
	public String[] blockquoteDefaultAttributeArray = {"cite"};

	// exclude attribute : formaction
	public String[] buttonDefaultAttributeArray = {"autofocus", "disabled", "form", "formenctype", "formmethod", "formnovalidate", "formtarget", "name", "type", "value"};
	public String[] canvasDefaultAttributeArray = {"height", "width"};
	public String[] captionDefaultAttributeArray = {"align"};
	public String[] colDefaultAttributeArray = {"align", "char", "charoff", "span", "valign", "width"};
	public String[] colgroupDefaultAttributeArray = {"align", "char", "charoff", "span", "valign", "width"};
	public String[] commandDefaultAttributeArray = {"type"};
	public String[] delDefaultAttributeArray = {"cite", "datetime"};
	public String[] detailsDefaultAttributeArray = {"open"};
	public String[] dirDefaultAttributeArray = {"compact"};
	public String[] divDefaultAttributeArray = {"align"};
	public String[] fieldsetDefaultAttributeArray = {"disabled", "form", "name"};
	public String[] fontDefaultAttributeArray = {"color", "face", "size"};
	public String[] formDefaultAttributeArray = {"accept", "accept-charset", "action", "autocomplete", "enctype", "method", "name", "novalidate", "target"};
	public String[] frameDefaultAttributeArray = {"frameborder", "longdesc", "marginheight", "marginwidth", "name", "noresize", "scrolling", "src"};
	public String[] framesetDefaultAttributeArray = {"cols", "rows"};
	public String[] h1Toh6DefaultAttributeArray = {"align"};
	public String[] headDefaultAttributeArray = {"profile"};
	public String[] hrDefaultAttributeArray = {"align", "noshade", "size", "width"};

	// exclude attribute : crossorigin, srcset
	public String[] imgDefaultAttributeArray = {"align", "alt", "border", "height", "hspace", "ismap", "longdesc", "sizes", "src", "usemap", "vspace", "width"};

	// exclude attribute : dirname, formaction
	public String[] inputDefaultAttributeArray = {"accept", "align", "alt", "autocomplete", "autofocus", "checked", "disabled", "form", "formenctype", "formmethod",
		"formnovalidate", "formtarget", "height", "list", "max", "maxlength", "min", "multiple", "name", "pattern", "placeholder", "readonly", "required", "size",
		"src", "step", "type", "value", "width"};

	public String[] insDefaultAttributeArray = {"cite", "datetime"};
	public String[] isindexDefaultAttributeArray = {"action", "prompt"};
	public String[] keygenDefaultAttributeArray = {"autofocus", "challenge", "disabled", "form", "keytype", "name"};
	public String[] labelDefaultAttributeArray = {"for", "form"};
	public String[] legendDefaultAttributeArray = {"align"};
	public String[] liDefaultAttributeArray = {"type", "value"};
	public String[] mapDefaultAttributeArray = {"name"};
	public String[] marqueeDefaultAttributeArray = {"width", "height", "direction", "behavior", "scrolldelay", "scrollamount", "bgcolor", "hspace", "vspace", "loop"};
	public String[] menuDefaultAttributeArray = {"type", "id"};
	public String[] meterDefaultAttributeArray = {"form", "high", "low", "max", "min", "optimum", "value"};

	// exclude attribute : reversed
	public String[] olDefaultAttributeArray = {"compact", "start", "type"};
	public String[] optgroupDefaultAttributeArray = {"disabled", "label"};
	public String[] optionDefaultAttributeArray = {"disabled", "label", "selected", "value"};
	public String[] outputDefaultAttributeArray = {"for", "form", "name"};
	public String[] pDefaultAttributeArray = {"align"};
	public String[] paramDefaultAttributeArray = {"name", "type", "value", "valuetype"};
	public String[] preDefaultAttributeArray = {"width"};
	public String[] progressDefaultAttributeArray = {"max", "value"};
	public String[] qDefaultAttributeArray = {"cite"};
	public String[] selectDefaultAttributeArray = {"autofocus", "disabled", "form", "multiple", "name", "required", "size"};

	// exclude attribute : srcset
	public String[] sourceDefaultAttributeArray = {"src", "media", "sizes", "type"};
	public String[] tableDefaultAttributeArray = {"align", "bgcolor", "border", "cellpadding", "cellspacing", "frame", "rules", "summary", "width"};
	public String[] tbodyDefaultAttributeArray = {"align", "char", "charoff", "valign"};

	// exclude attribute : nowrap
	public String[] tdDefaultAttributeArray = {"abbr", "align", "axis", "bgcolor", "char", "charoff", "colspan", "headers", "height", "rowspan", "scope", "valign", "width"};
	public String[] textareaDefaultAttributeArray = {"autofocus", "cols", "dirname", "disabled", "form", "maxlength", "name", "placeholder", "readonly", "required", "rows", "wrap"};
	public String[] tfootDefaultAttributeArray = {"align", "char", "charoff", "valign"};

	// exclude attribute : nowrap, sorted
	public String[] thDefaultAttributeArray = {"abbr", "align", "axis", "bgcolor", "char", "charoff", "colspan", "headers", "height", "rowspan", "scope", "valign", "width"};
	public String[] theadDefaultAttributeArray = {"align", "char", "charoff", "valign"};
	public String[] timeDefaultAttributeArray = {"datetime"};
	public String[] trDefaultAttributeArray = {"align", "bgcolor", "char", "charoff", "valign"};
	public String[] trackDefaultAttributeArray = {"default", "kind", "label", "src", "srclang"};
	public String[] ulDefaultAttributeArray = {"compact", "type"};
	public String[] videoDefaultAttributeArray = {"autoplay", "controls", "height", "loop", "muted", "poster", "preload", "src", "width"};

	PolicyFactory NAVER_DEFAULT_POLICY;
	PolicyFactory OVERRIDED_POLICY_DEFINITION;

	//	private static final Pattern NAME = Pattern.compile("[a-zA-Z0-9\\-_\\$]+");

	@Before
	public void setUp() throws Exception {

		// todo security team have to confirm the global attributes (mdn or w3schools or something else)

		// a
		String[] aAttributeArray = addAll(aDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// area
		String[] areaAttributeArray = addAll(areaDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// audio
		String[] audioAttributeArray = addAll(audioDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// blockquote
		String[] blockquoteAttributeArray = addAll(blockquoteDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// button
		String[] buttonAttributeArray = addAll(buttonDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// canvas
		String[] canvasAttributeArray = addAll(canvasDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// caption
		String[] captionAttributeArray = addAll(captionDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// col
		String[] colAttributeArray = addAll(colDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// colgroup
		String[] colgroupAttributeArray = addAll(colgroupDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// del
		String[] delAttributeArray = addAll(delDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// details
		String[] detailsAttributeArray = addAll(detailsDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// div
		String[] divAttributeArray = addAll(divDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// fieldset
		String[] fieldsetAttributeArray = addAll(fieldsetDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// form
		String[] formAttributeArray = addAll(formDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// h1 - h6
		String[] h1Toh6AttributeArray = addAll(h1Toh6DefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// head
		String[] headAttributeArray = addAll(headDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// hr
		String[] hrAttributeArray = addAll(hrDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// img
		String[] imgAttributeArray = addAll(imgDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// input
		String[] inputAttributeArray = addAll(inputDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// ins
		String[] insAttributeArray = addAll(insDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// keygen
		String[] keygenAttributeArray = addAll(keygenDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// label
		String[] labelAttributeArray = addAll(labelDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// legend
		String[] legendAttributeArray = addAll(legendDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// li
		String[] liAttributeArray = addAll(liDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// map
		String[] mapAttributeArray = addAll(mapDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// meter
		String[] meterAttributeArray = addAll(meterDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// ol
		String[] olAttributeArray = addAll(olDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// optgroup
		String[] optgroupAttributeArray = addAll(optgroupDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// option
		String[] optionAttributeArray = addAll(optionDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// output
		String[] outputAttributeArray = addAll(outputDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// p
		String[] pAttributeArray = addAll(pDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// param
		String[] paramAttributeArray = addAll(paramDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// pre
		String[] preAttributeArray = addAll(preDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// progress
		String[] progressAttributeArray = addAll(progressDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// q
		String[] qAttributeArray = addAll(qDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// select
		String[] selectAttributeArray = addAll(selectDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// source
		String[] sourceAttributeArray = addAll(sourceDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// table
		String[] tableAttributeArray = addAll(tableDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// tbody
		String[] tbodyAttributeArray = addAll(tbodyDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// td
		String[] tdAttributeArray = addAll(tdDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// textarea
		String[] textareaAttributeArray = addAll(textareaDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// tfoot
		String[] tfootAttributeArray = addAll(tfootDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// th
		String[] thAttributeArray = addAll(thDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// thead
		String[] theadAttributeArray = addAll(theadDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// time
		String[] timeAttributeArray = addAll(timeDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// tr
		String[] trAttributeArray = addAll(trDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// track
		String[] trackAttributeArray = addAll(trackDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// ul
		String[] ulAttributeArray = addAll(ulDefaultAttributeArray, w3schoolsGlobalAttributeArray);
		// video
		String[] videoAttributeArray = addAll(videoDefaultAttributeArray, w3schoolsGlobalAttributeArray);

		NAVER_DEFAULT_POLICY = new HtmlPolicyBuilder()

			.allowElements("a")
			.allowAttributes(aAttributeArray).onElements("a")
			// .allowAttributes("href").matching().onElements("a")
			.disallowAttributes("style").onElements("a")

			.allowElements("abbr")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("abbr")

			.allowElements("acronym")

			.allowElements("adress")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("adress")

			.allowElements("applet")
			.allowAttributes(appletDefaultAttributeArray).onElements("applet")

			.allowElements("area")
			.allowAttributes(areaAttributeArray).onElements("area")

			.allowElements("article")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("article")

			.allowElements("aside")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("aside")

			.allowElements("audio")
			.allowAttributes(audioAttributeArray).onElements("audio")

			.allowElements("b")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("b")

			// base(exclude element)

			.allowElements("basefont")
			.allowAttributes(basefontDefaultAttributeArray).onElements("basefont")

			.allowElements("bdi")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("bdi")

			.allowElements("bdo")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("bdo")

			.allowElements("big")

			.allowElements("blockquote")
			.allowAttributes(blockquoteAttributeArray).onElements("blockquote")

			// body(exclude element)

			.allowElements("br")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("br")

			.allowElements("button")
			.allowAttributes(buttonAttributeArray).onElements("button")

			.allowElements("canvas")
			.allowAttributes(canvasAttributeArray).onElements("canvas")

			.allowElements("caption")
			.allowAttributes(captionAttributeArray).onElements("caption")

			.allowElements("center")

			.allowElements("cite")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("cite")

			.allowElements("code")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("code")

			.allowElements("col")
			.allowAttributes(colAttributeArray).onElements("col")

			.allowElements("colgroup")
			.allowAttributes(colgroupAttributeArray).onElements("colgroup")

			.allowElements("command")
			.allowAttributes(commandDefaultAttributeArray).onElements("command")

			// data element(exclude element)

			.allowElements("datalist")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("datalist")

			.allowElements("dd")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("dd")

			.allowElements("del")
			.allowAttributes(delAttributeArray).onElements("del")

			.allowElements("details")
			.allowAttributes(detailsAttributeArray).onElements("details")

			.allowElements("dfn")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("dfn")

			// dialog(exclude element)

			.allowElements("dir")
			.allowAttributes(dirDefaultAttributeArray).onElements("dir")

			.allowElements("div")
			.allowAttributes(divAttributeArray).onElements("div")

			.allowElements("dl")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("dl")

			.allowElements("dt")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("dt")

			.allowElements("em")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("em")

			// embed(exclude element)

			.allowElements("fieldset")
			.allowAttributes(fieldsetAttributeArray).onElements("fieldset")

			.allowElements("figcaption")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("figcaption")

			.allowElements("figure")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("figure")

			.allowElements("font")
			.allowAttributes(fontDefaultAttributeArray).onElements("font")

			.allowElements("footer")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("footer")

			.allowElements("form")
			.allowAttributes(formAttributeArray).onElements("form")

			.allowElements("frame")
			.allowAttributes(frameDefaultAttributeArray).onElements("frame")

			.allowElements("frameset")
			.allowAttributes(framesetDefaultAttributeArray).onElements("frameset")

			.allowElements("h1", "h2", "h3", "h4", "h5", "h6")
			.allowAttributes(h1Toh6AttributeArray).onElements("h1", "h2", "h3", "h4", "h5", "h6")

			.allowElements("head")
			.allowAttributes(headAttributeArray).onElements("head")

			.allowElements("header")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("header")

			.allowElements("hgroup")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("hgroup")

			.allowElements("hr")
			.allowAttributes(hrAttributeArray).onElements("hr")

			.allowElements("html") // xmlns(exclude attribute)
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("html")

			.allowElements("i")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("i")

			// iframe(exclude element)

			.allowElements("img")
			.allowAttributes(imgAttributeArray).onElements("img")

			.allowElements("input")
			.allowAttributes(inputAttributeArray).onElements("input")

			.allowElements("ins")
			.allowAttributes(insAttributeArray).onElements("ins")

			.allowElements("isindex")
			.allowAttributes(isindexDefaultAttributeArray).onElements("isindex")

			.allowElements("kbd")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("kbd")

			.allowElements("keygen")
			.allowAttributes(keygenAttributeArray).onElements("keygen")

			.allowElements("label")
			.allowAttributes(labelAttributeArray).onElements("label")

			.allowElements("legend")
			.allowAttributes(legendAttributeArray).onElements("legend")

			.allowElements("li")
			.allowAttributes(liAttributeArray).onElements("li")

			// link(exclude element)
			// main(exclude element)

			.allowElements("map")
			.allowAttributes(mapAttributeArray).onElements("map")

			.allowElements("marquee")
			.allowAttributes(marqueeDefaultAttributeArray).onElements("marquee")

			.allowElements("menu")
			.allowAttributes(menuDefaultAttributeArray).onElements("menu")

			.allowElements("mark")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("mark")

			// meta(exclude element)

			// nobr(exclude element) https://developer.mozilla.org/en-US/docs/Web/HTML/Element/nobr

			.allowElements("meter")
			.allowAttributes(meterAttributeArray).onElements("meter")

			.allowElements("nav")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("nav")

			.allowElements("noframes")

			.allowElements("noscript")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("noscript")

			// object(exclude element)

			.allowElements("ol")
			.allowAttributes(olAttributeArray).onElements("ol")

			.allowElements("optgroup")
			.allowAttributes(optgroupAttributeArray).onElements("optgroup")

			.allowElements("option")
			.allowAttributes(optionAttributeArray).onElements("option")

			.allowElements("output")
			.allowAttributes(outputAttributeArray).onElements("output")

			.allowElements("p")
			.allowAttributes(pAttributeArray).onElements("p")

			.allowElements("param")
			.allowAttributes(paramAttributeArray).onElements("param")

			// picture(exclude element)

			.allowElements("pre")
			.allowAttributes(preAttributeArray).onElements("pre")

			.allowElements("progress")
			.allowAttributes(progressAttributeArray).onElements("progress")

			.allowElements("q")
			.allowAttributes(qAttributeArray).onElements("q")

			.allowElements("rp")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("rp")

			.allowElements("rt")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("rt")

			.allowElements("ruby")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("ruby")

			.allowElements("s")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("s")

			.allowElements("samp")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("samp")

			// script(exclude element)

			.allowElements("section")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("section")

			.allowElements("select")
			.allowAttributes(selectAttributeArray).onElements("select")

			.allowElements("small")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("small")

			.allowElements("source")
			.allowAttributes(sourceAttributeArray).onElements("source")

			.allowElements("span")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("span")

			.allowElements("strike")

			.allowElements("strong")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("strong")

			// style(exclude element)

			.allowElements("sub")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("sub")

			.allowElements("summary")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("summary")

			.allowElements("sup")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("sup")

			// svg(exclude element)

			.allowElements("table")
			.allowAttributes(tableAttributeArray).onElements("table")

			.allowElements("tbody")
			.allowAttributes(tbodyAttributeArray).onElements("tbody")

			.allowElements("td")
			.allowAttributes(tdAttributeArray).onElements("td")

			// template(exclude element)

			.allowElements("textarea")
			.allowAttributes(textareaAttributeArray).onElements("textarea")

			.allowElements("tfoot")
			.allowAttributes(tfootAttributeArray).onElements("tfoot")

			.allowElements("th")
			.allowAttributes(thAttributeArray).onElements("th")

			.allowElements("thead")
			.allowAttributes(theadAttributeArray).onElements("thead")

			.allowElements("time")
			.allowAttributes(timeAttributeArray).onElements("time")

			.allowElements("title")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("title")

			.allowElements("tr")
			.allowAttributes(trAttributeArray).onElements("tr")

			.allowElements("track")
			.allowAttributes(trackAttributeArray).onElements("track")

			.allowElements("tt")

			.allowElements("u")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("u")

			.allowElements("ul")
			.allowAttributes(ulAttributeArray).onElements("ul")

			.allowElements("var")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("var")

			.allowElements("video")
			.allowAttributes(videoAttributeArray).onElements("video")

			.allowElements("wbr")
			.allowAttributes(w3schoolsGlobalAttributeArray).onElements("wbr")

			.allowUrlProtocols("https", "http")
			.toFactory();



		/* todo how to make notAllowedPattern rules
		<attribute name="href">
			<notAllowedPattern><![CDATA[(?i:j\\*a\\*v\\*a\\*s\\*c\\*r\\*i\\*p\\*t\\*:)]]></notAllowedPattern>
			<notAllowedPattern><![CDATA[&[#\\%x]+[\da-fA-F][\da-fA-F]+]]></notAllowedPattern>
		</attribute>
		*/

		// todo find the way how to make policy override easy
		OVERRIDED_POLICY_DEFINITION = NAVER_DEFAULT_POLICY.and(
			new HtmlPolicyBuilder()
				.allowElements("a")
				.allowAttributes(aAttributeArray).onElements("a")
				.toFactory());
	}

	@Test
	public void aElementTest() {

		String dirty1 = "<p>"
			+ "<a href='java\0script:bad()'>1</a>"
			+ "<a style='color: red; font-weight; expression(foo());, direction: rtl; font-weight: bold'>2</a>"
			+ "<a href='foo.html'>3</a>"
			+ "<a href='http://outside.org/'>5</a>"
			+ "</p>";
		String clean = NAVER_DEFAULT_POLICY.sanitize(dirty1);
		System.out.println(clean);
	}

	private static String[] addAll(String[] array1, String[] array2) {
		String[] tempArr = new String[array1.length + array2.length];
		System.arraycopy(array1, 0, tempArr, 0, array1.length);
		System.arraycopy(array2, 0, tempArr, array1.length, array2.length);
		return tempArr;
	}

}
