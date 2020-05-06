package org.owasp.naver;

import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;

public class NaverHtmlPolicy {

	// todo check element
	//	<element name="body" disable="true" /> <!-- <BODY ONLOAD=alert("XSS")>, <BODY BACKGROUND="javascript:alert('XSS')"> -->
	//	<element name="embed" disable="true" />
	//	<element name="iframe" disable="true" /> <!-- <IFRAME SRC=”http://hacker-site.com/xss.html”> -->
	//	<element name="meta" disable="true" />
	//	<element name="object" disable="true" />
	//	<element name="script" disable="true" /> <!-- <SCRIPT> alert(“XSS”); </SCRIPT> -->
	//	<element name="style" disable="true" />
	//	<element name="link" disable="true" />
	//	<element name="base" disable="true" />

	// todo global attribute duplicate check
	private String[] mdnGlobalAttributeArray = {"accesskey", "class", "dir", "exportparts", "hidden", "id", "lang", "style", "tabindex", "title"}; // exclude attribute : autocapitalize contenteditable contextmenu data-* draggable dropzone inputmode is itemid itemprop itemref itemscope itemtype part slot spellcheck translate

	// todo MDN doesn't have media attribute (but w3schools have)
	private String[] aDefaultAttributeArray = {"charset", "coords", "href", "hreflang", "media", "name", "rel", "rev", "shape", "target", "type"};

	// abbr(only include global attributes)
	// acronym(only include global attributes)
	// address(only include global attributes)

	private String[] appletDefaultAttributeArray = {"code", "object", "align", "alt", "archive", "codebase", "height", "hspace", "name", "vspace", "width", "src"}; // exclude attribute : datafld, datasrc, mayscript
	private String[] areaDefaultAttributeArray = {"alt", "coords", "href", "hreflang", "media", "nohref", "rel", "shape", "target", "type", "name", "tabindex"}; // exclude attribute : download, ping, referrerpolicy

	// article(only include global attributes)
	// aside(only include global attributes)

	private String[] audioDefaultAttributeArray = {"autoplay", "controls", "loop", "muted", "preload", "src"}; // exclude attribute : crossorigin, currentTime, disableRemotePlayback, duration

	// b(only include global attributes)
	// base(exclude element)

	private String[] basefontDefaultAttributeArray = {"color", "face", "size"};

	// bdi(only include global attributes)
	// bdo(only include global attributes)
	// big(only include global attributes)

	private String[] blockquoteDefaultAttributeArray = {"cite"};

	// body(exclude element)
	// br(only include global attributes)

	private String[] buttonDefaultAttributeArray = {"autofocus", "disabled", "form", "formenctype", "formmethod", "formnovalidate", "formtarget", "name", "type", "value", "autocomplete"}; // exclude attribute : formaction
	private String[] canvasDefaultAttributeArray = {"height", "width"}; // exclude attribute : moz-opaque
	private String[] captionDefaultAttributeArray = {"align"};

	// center(don't include any attribute. but not exclude element)
	// cite(only include global attributes)
	// code(only include global attributes)

	private String[] colDefaultAttributeArray = {"align", "char", "charoff", "span", "valign", "width", "bgcolor"};
	private String[] colgroupDefaultAttributeArray = {"align", "char", "charoff", "span", "valign", "bgcolor"};
	private String[] commandDefaultAttributeArray = {"checked", "disabled", "icon", "label", "radiogroup", "type"};

	// data(exclude element)
	// datalist(only include global attributes)

	private String[] ddDefaultAttributeArray = {"nowrap"};
	private String[] delDefaultAttributeArray = {"cite", "datetime"};
	private String[] detailsDefaultAttributeArray = {"open"};

	// dfn(only include global attributes)
	// dialog(exclude element)

	private String[] dirDefaultAttributeArray = {"compact"};

	// div(only include global attributes)
	// dl(only include global attributes)
	// dt(only include global attributes)
	// em(only include global attributes)
	// embed(exclude element)

	private String[] fieldsetDefaultAttributeArray = {"disabled", "form", "name"};

	// figcaption(only include global attributes)
	// figure(only include global attributes)

	private String[] fontDefaultAttributeArray = {"color", "face", "size"};

	// footer(only include global attributes)

	private String[] formDefaultAttributeArray = {"accept", "accept-charset", "action", "autocomplete", "enctype", "method", "name", "novalidate", "target", "rel"}; // exclude attribute : autocapitalize
	private String[] frameDefaultAttributeArray = {"frameborder", "marginheight", "marginwidth", "name", "noresize", "scrolling", "src"};
	private String[] framesetDefaultAttributeArray = {"cols", "rows"};

	// h1-h6(only include global attributes)

	private String[] headDefaultAttributeArray = {"profile"};

	// header(only include global attributes)
	// hgroup(only include global attributes)

	private String[] hrDefaultAttributeArray = {"align", "noshade", "size", "width", "color"};
	private String[] htmlDefaultAttributeArray = {"manifest", "version"}; // exclude attribute : xmlns

	// i(only include global attributes)
	// iframe(exclude element)

	private String[] imgDefaultAttributeArray = {"align", "alt", "border", "height", "hspace", "ismap", "longdesc", "sizes", "src", "usemap", "vspace", "width", "name"}; // exclude attribute : crossorigin, srcset, decoding, importance, intrinsicsize, loading, referrerpolicy
	private String[] inputDefaultAttributeArray = {"accept", "alt", "autocomplete", "autofocus", "checked", "disabled", "form", "formenctype", "formmethod",
		"formnovalidate", "formtarget", "height", "list", "max", "maxlength", "min", "multiple", "name", "pattern", "placeholder", "readonly", "required", "size",
		"src", "step", "type", "value", "width"}; // exclude attribute : dirname, formaction, capture, inputmode, minlength, autocorrect, incremental, mozactionhint, orient, results, webkitdirectory
	private String[] insDefaultAttributeArray = {"cite", "datetime"};
	private String[] isindexDefaultAttributeArray = {"action", "prompt"};

	// kbd(only include global attributes)

	private String[] keygenDefaultAttributeArray = {"autofocus", "challenge", "disabled", "form", "keytype", "name"};
	private String[] labelDefaultAttributeArray = {"for", "form"};

	// legend(only include global attributes)

	private String[] liDefaultAttributeArray = {"type", "value"};

	// link(exclude element)
	// main(exclude element)

	private String[] mapDefaultAttributeArray = {"name"};
	private String[] marqueeDefaultAttributeArray = {"width", "height", "direction", "behavior", "scrolldelay", "scrollamount", "bgcolor", "hspace", "vspace", "loop"}; // exclude attribute : truespeed
	private String[] menuDefaultAttributeArray = {"type", "label"};

	// mark(only include global attributes)

	// meta(exclude element)
	// nobr(exclude element) https://developer.mozilla.org/en-US/docs/Web/HTML/Element/nobr


	private String[] meterDefaultAttributeArray = {"form", "high", "low", "max", "min", "optimum", "value"};

	// exclude attribute : reversed
	private String[] olDefaultAttributeArray = {"compact", "start", "type"};
	private String[] optgroupDefaultAttributeArray = {"disabled", "label"};
	private String[] optionDefaultAttributeArray = {"disabled", "label", "selected", "value"};
	private String[] outputDefaultAttributeArray = {"for", "form", "name"};
	private String[] pDefaultAttributeArray = {"align"};
	private String[] paramDefaultAttributeArray = {"name", "type", "value", "valuetype"};
	private String[] preDefaultAttributeArray = {"width"};
	private String[] progressDefaultAttributeArray = {"max", "value"};
	private String[] qDefaultAttributeArray = {"cite"};
	private String[] selectDefaultAttributeArray = {"autofocus", "disabled", "form", "multiple", "name", "required", "size"};

	// exclude attribute : srcset
	private String[] sourceDefaultAttributeArray = {"src", "media", "sizes", "type"};
	private String[] tableDefaultAttributeArray = {"align", "bgcolor", "border", "cellpadding", "cellspacing", "frame", "rules", "summary", "width"};
	private String[] tbodyDefaultAttributeArray = {"align", "char", "charoff", "valign"};

	// exclude attribute : nowrap
	private String[] tdDefaultAttributeArray = {"abbr", "align", "axis", "bgcolor", "char", "charoff", "colspan", "headers", "height", "rowspan", "scope", "valign", "width"};
	private String[] textareaDefaultAttributeArray = {"autofocus", "cols", "dirname", "disabled", "form", "maxlength", "name", "placeholder", "readonly", "required", "rows", "wrap"};
	private String[] tfootDefaultAttributeArray = {"align", "char", "charoff", "valign"};

	// exclude attribute : nowrap, sorted
	private String[] thDefaultAttributeArray = {"abbr", "align", "axis", "bgcolor", "char", "charoff", "colspan", "headers", "height", "rowspan", "scope", "valign", "width"};
	private String[] theadDefaultAttributeArray = {"align", "char", "charoff", "valign"};
	private String[] timeDefaultAttributeArray = {"datetime"};
	private String[] trDefaultAttributeArray = {"align", "bgcolor", "char", "charoff", "valign"};
	private String[] trackDefaultAttributeArray = {"default", "kind", "label", "src", "srclang"};
	private String[] ulDefaultAttributeArray = {"compact", "type"};
	private String[] videoDefaultAttributeArray = {"autoplay", "controls", "height", "loop", "muted", "poster", "preload", "src", "width"};

	private static PolicyFactory NAVER_DEFAULT_POLICY;
	private static NaverHtmlPolicy instance;

	private NaverHtmlPolicy() {
		// a
		String[] aAttributeArray = addAll(aDefaultAttributeArray, mdnGlobalAttributeArray);
		// area
		String[] areaAttributeArray = addAll(areaDefaultAttributeArray, mdnGlobalAttributeArray);
		// audio
		String[] audioAttributeArray = addAll(audioDefaultAttributeArray, mdnGlobalAttributeArray);
		// basefont
		String[] basefontAttributeArray = addAll(basefontDefaultAttributeArray, mdnGlobalAttributeArray);
		// blockquote
		String[] blockquoteAttributeArray = addAll(blockquoteDefaultAttributeArray, mdnGlobalAttributeArray);
		// button
		String[] buttonAttributeArray = addAll(buttonDefaultAttributeArray, mdnGlobalAttributeArray);
		// canvas
		String[] canvasAttributeArray = addAll(canvasDefaultAttributeArray, mdnGlobalAttributeArray);
		// caption
		String[] captionAttributeArray = addAll(captionDefaultAttributeArray, mdnGlobalAttributeArray);
		// col
		String[] colAttributeArray = addAll(colDefaultAttributeArray, mdnGlobalAttributeArray);
		// colgroup
		String[] colgroupAttributeArray = addAll(colgroupDefaultAttributeArray, mdnGlobalAttributeArray);
		// command
		String[] commandAttributeArray = addAll(commandDefaultAttributeArray, mdnGlobalAttributeArray);
		// dd
		String[] ddAttributeArray = addAll(ddDefaultAttributeArray, mdnGlobalAttributeArray);
		// del
		String[] delAttributeArray = addAll(delDefaultAttributeArray, mdnGlobalAttributeArray);
		// details
		String[] detailsAttributeArray = addAll(detailsDefaultAttributeArray, mdnGlobalAttributeArray);
		// dir
		String[] dirAttributeArray = addAll(dirDefaultAttributeArray, mdnGlobalAttributeArray);
		// fieldset
		String[] fieldsetAttributeArray = addAll(fieldsetDefaultAttributeArray, mdnGlobalAttributeArray);
		// font
		String[] fontAttributeArray = addAll(fontDefaultAttributeArray, mdnGlobalAttributeArray);
		// form
		String[] formAttributeArray = addAll(formDefaultAttributeArray, mdnGlobalAttributeArray);
		// frame
		String[] frameAttributeArray = addAll(frameDefaultAttributeArray, mdnGlobalAttributeArray);
		// frameset
		String[] framesetAttributeArray = addAll(framesetDefaultAttributeArray, mdnGlobalAttributeArray);
		// head
		String[] headAttributeArray = addAll(headDefaultAttributeArray, mdnGlobalAttributeArray);
		// hr
		String[] hrAttributeArray = addAll(hrDefaultAttributeArray, mdnGlobalAttributeArray);
		// html
		String[] htmlAttributeArray = addAll(htmlDefaultAttributeArray, mdnGlobalAttributeArray);
		// img
		String[] imgAttributeArray = addAll(imgDefaultAttributeArray, mdnGlobalAttributeArray);
		// input
		String[] inputAttributeArray = addAll(inputDefaultAttributeArray, mdnGlobalAttributeArray);
		// ins
		String[] insAttributeArray = addAll(insDefaultAttributeArray, mdnGlobalAttributeArray);
		// isindex
		String[] isindexAttributeArray = addAll(isindexDefaultAttributeArray, mdnGlobalAttributeArray);
		// keygen
		String[] keygenAttributeArray = addAll(keygenDefaultAttributeArray, mdnGlobalAttributeArray);
		// label
		String[] labelAttributeArray = addAll(labelDefaultAttributeArray, mdnGlobalAttributeArray);
		// li
		String[] liAttributeArray = addAll(liDefaultAttributeArray, mdnGlobalAttributeArray);
		// map
		String[] mapAttributeArray = addAll(mapDefaultAttributeArray, mdnGlobalAttributeArray);
		// menu
		String[] menuAttributeArray = addAll(menuDefaultAttributeArray, mdnGlobalAttributeArray);
		// meter
		String[] meterAttributeArray = addAll(meterDefaultAttributeArray, mdnGlobalAttributeArray);
		// ol
		String[] olAttributeArray = addAll(olDefaultAttributeArray, mdnGlobalAttributeArray);
		// optgroup
		String[] optgroupAttributeArray = addAll(optgroupDefaultAttributeArray, mdnGlobalAttributeArray);
		// option
		String[] optionAttributeArray = addAll(optionDefaultAttributeArray, mdnGlobalAttributeArray);
		// output
		String[] outputAttributeArray = addAll(outputDefaultAttributeArray, mdnGlobalAttributeArray);
		// p
		String[] pAttributeArray = addAll(pDefaultAttributeArray, mdnGlobalAttributeArray);
		// param
		String[] paramAttributeArray = addAll(paramDefaultAttributeArray, mdnGlobalAttributeArray);
		// pre
		String[] preAttributeArray = addAll(preDefaultAttributeArray, mdnGlobalAttributeArray);
		// progress
		String[] progressAttributeArray = addAll(progressDefaultAttributeArray, mdnGlobalAttributeArray);
		// q
		String[] qAttributeArray = addAll(qDefaultAttributeArray, mdnGlobalAttributeArray);
		// select
		String[] selectAttributeArray = addAll(selectDefaultAttributeArray, mdnGlobalAttributeArray);
		// source
		String[] sourceAttributeArray = addAll(sourceDefaultAttributeArray, mdnGlobalAttributeArray);
		// table
		String[] tableAttributeArray = addAll(tableDefaultAttributeArray, mdnGlobalAttributeArray);
		// tbody
		String[] tbodyAttributeArray = addAll(tbodyDefaultAttributeArray, mdnGlobalAttributeArray);
		// td
		String[] tdAttributeArray = addAll(tdDefaultAttributeArray, mdnGlobalAttributeArray);
		// textarea
		String[] textareaAttributeArray = addAll(textareaDefaultAttributeArray, mdnGlobalAttributeArray);
		// tfoot
		String[] tfootAttributeArray = addAll(tfootDefaultAttributeArray, mdnGlobalAttributeArray);
		// th
		String[] thAttributeArray = addAll(thDefaultAttributeArray, mdnGlobalAttributeArray);
		// thead
		String[] theadAttributeArray = addAll(theadDefaultAttributeArray, mdnGlobalAttributeArray);
		// time
		String[] timeAttributeArray = addAll(timeDefaultAttributeArray, mdnGlobalAttributeArray);
		// tr
		String[] trAttributeArray = addAll(trDefaultAttributeArray, mdnGlobalAttributeArray);
		// track
		String[] trackAttributeArray = addAll(trackDefaultAttributeArray, mdnGlobalAttributeArray);
		// ul
		String[] ulAttributeArray = addAll(ulDefaultAttributeArray, mdnGlobalAttributeArray);
		// video
		String[] videoAttributeArray = addAll(videoDefaultAttributeArray, mdnGlobalAttributeArray);

		NAVER_DEFAULT_POLICY = new HtmlPolicyBuilder()

			.allowElements("a")
			.allowAttributes(aAttributeArray).onElements("a")
			// .allowAttributes("href").matching().onElements("a")
			.disallowAttributes("style").onElements("a")

			.allowElements("abbr")
			.allowAttributes(mdnGlobalAttributeArray).onElements("abbr")

			.allowElements("acronym")
			.allowAttributes(mdnGlobalAttributeArray).onElements("acronym")

			.allowElements("address")
			.allowAttributes(mdnGlobalAttributeArray).onElements("address")

			.allowElements("applet")
			.allowAttributes(appletDefaultAttributeArray).onElements("applet")

			.allowElements("area")
			.allowAttributes(areaAttributeArray).onElements("area")

			.allowElements("article")
			.allowAttributes(mdnGlobalAttributeArray).onElements("article")

			.allowElements("aside")
			.allowAttributes(mdnGlobalAttributeArray).onElements("aside")

			.allowElements("audio")
			.allowAttributes(audioAttributeArray).onElements("audio")

			.allowElements("b")
			.allowAttributes(mdnGlobalAttributeArray).onElements("b")

			.allowElements("basefont")
			.allowAttributes(basefontAttributeArray).onElements("basefont")

			.allowElements("bdi")
			.allowAttributes(mdnGlobalAttributeArray).onElements("bdi")

			.allowElements("bdo")
			.allowAttributes(mdnGlobalAttributeArray).onElements("bdo")

			.allowElements("big")
			.allowAttributes(mdnGlobalAttributeArray).onElements("big")

			.allowElements("blockquote")
			.allowAttributes(blockquoteAttributeArray).onElements("blockquote")

			.allowElements("br")
			.allowAttributes(mdnGlobalAttributeArray).onElements("br")

			.allowElements("button")
			.allowAttributes(buttonAttributeArray).onElements("button")

			.allowElements("canvas")
			.allowAttributes(canvasAttributeArray).onElements("canvas")

			.allowElements("caption")
			.allowAttributes(captionAttributeArray).onElements("caption")

			.allowElements("center")

			.allowElements("cite")
			.allowAttributes(mdnGlobalAttributeArray).onElements("cite")

			.allowElements("code")
			.allowAttributes(mdnGlobalAttributeArray).onElements("code")

			.allowElements("col")
			.allowAttributes(colAttributeArray).onElements("col")

			.allowElements("colgroup")
			.allowAttributes(colgroupAttributeArray).onElements("colgroup")

			.allowElements("command")
			.allowAttributes(commandAttributeArray).onElements("command")

			.allowElements("datalist")
			.allowAttributes(mdnGlobalAttributeArray).onElements("datalist")

			.allowElements("dd")
			.allowAttributes(ddAttributeArray).onElements("dd")

			.allowElements("del")
			.allowAttributes(delAttributeArray).onElements("del")

			.allowElements("details")
			.allowAttributes(detailsAttributeArray).onElements("details")

			.allowElements("dfn")
			.allowAttributes(mdnGlobalAttributeArray).onElements("dfn")

			.allowElements("dir")
			.allowAttributes(dirAttributeArray).onElements("dir")

			.allowElements("div")
			.allowAttributes(mdnGlobalAttributeArray).onElements("div")

			.allowElements("dl")
			.allowAttributes(mdnGlobalAttributeArray).onElements("dl")

			.allowElements("dt")
			.allowAttributes(mdnGlobalAttributeArray).onElements("dt")

			.allowElements("em")
			.allowAttributes(mdnGlobalAttributeArray).onElements("em")

			.allowElements("fieldset")
			.allowAttributes(fieldsetAttributeArray).onElements("fieldset")

			.allowElements("figcaption")
			.allowAttributes(mdnGlobalAttributeArray).onElements("figcaption")

			.allowElements("figure")
			.allowAttributes(mdnGlobalAttributeArray).onElements("figure")

			.allowElements("font")
			.allowAttributes(fontAttributeArray).onElements("font")

			.allowElements("footer")
			.allowAttributes(mdnGlobalAttributeArray).onElements("footer")

			.allowElements("form")
			.allowAttributes(formAttributeArray).onElements("form")

			.allowElements("frame")
			.allowAttributes(frameAttributeArray).onElements("frame")

			.allowElements("frameset")
			.allowAttributes(framesetAttributeArray).onElements("frameset")

			.allowElements("h1", "h2", "h3", "h4", "h5", "h6")
			.allowAttributes(mdnGlobalAttributeArray).onElements("h1", "h2", "h3", "h4", "h5", "h6")

			.allowElements("head")
			.allowAttributes(headAttributeArray).onElements("head")

			.allowElements("header")
			.allowAttributes(mdnGlobalAttributeArray).onElements("header")

			.allowElements("hgroup")
			.allowAttributes(mdnGlobalAttributeArray).onElements("hgroup")

			.allowElements("hr")
			.allowAttributes(hrAttributeArray).onElements("hr")

			.allowElements("html")
			.allowAttributes(htmlAttributeArray).onElements("html")

			.allowElements("i")
			.allowAttributes(mdnGlobalAttributeArray).onElements("i")

			.allowElements("img")
			.allowAttributes(imgAttributeArray).onElements("img")

			.allowElements("input")
			.allowAttributes(inputAttributeArray).onElements("input")

			.allowElements("ins")
			.allowAttributes(insAttributeArray).onElements("ins")

			.allowElements("isindex")
			.allowAttributes(isindexAttributeArray).onElements("isindex")

			.allowElements("kbd")
			.allowAttributes(mdnGlobalAttributeArray).onElements("kbd")

			.allowElements("keygen")
			.allowAttributes(keygenAttributeArray).onElements("keygen")

			.allowElements("label")
			.allowAttributes(labelAttributeArray).onElements("label")

			.allowElements("legend")
			.allowAttributes(mdnGlobalAttributeArray).onElements("legend")

			.allowElements("li")
			.allowAttributes(liAttributeArray).onElements("li")

			.allowElements("map")
			.allowAttributes(mapAttributeArray).onElements("map")

			.allowElements("marquee")
			.allowAttributes(marqueeDefaultAttributeArray).onElements("marquee")

			.allowElements("menu")
			.allowAttributes(menuAttributeArray).onElements("menu")

			.allowElements("mark")
			.allowAttributes(mdnGlobalAttributeArray).onElements("mark")

			.allowElements("meter")
			.allowAttributes(meterAttributeArray).onElements("meter")

			.allowElements("nav")
			.allowAttributes(mdnGlobalAttributeArray).onElements("nav")

			.allowElements("noframes")

			.allowElements("noscript")
			.allowAttributes(mdnGlobalAttributeArray).onElements("noscript")

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
			.allowAttributes(mdnGlobalAttributeArray).onElements("rp")

			.allowElements("rt")
			.allowAttributes(mdnGlobalAttributeArray).onElements("rt")

			.allowElements("ruby")
			.allowAttributes(mdnGlobalAttributeArray).onElements("ruby")

			.allowElements("s")
			.allowAttributes(mdnGlobalAttributeArray).onElements("s")

			.allowElements("samp")
			.allowAttributes(mdnGlobalAttributeArray).onElements("samp")

			// script(exclude element)

			.allowElements("section")
			.allowAttributes(mdnGlobalAttributeArray).onElements("section")

			.allowElements("select")
			.allowAttributes(selectAttributeArray).onElements("select")

			.allowElements("small")
			.allowAttributes(mdnGlobalAttributeArray).onElements("small")

			.allowElements("source")
			.allowAttributes(sourceAttributeArray).onElements("source")

			.allowElements("span")
			.allowAttributes(mdnGlobalAttributeArray).onElements("span")

			.allowElements("strike")

			.allowElements("strong")
			.allowAttributes(mdnGlobalAttributeArray).onElements("strong")

			// style(exclude element)

			.allowElements("sub")
			.allowAttributes(mdnGlobalAttributeArray).onElements("sub")

			.allowElements("summary")
			.allowAttributes(mdnGlobalAttributeArray).onElements("summary")

			.allowElements("sup")
			.allowAttributes(mdnGlobalAttributeArray).onElements("sup")

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
			.allowAttributes(mdnGlobalAttributeArray).onElements("title")

			.allowElements("tr")
			.allowAttributes(trAttributeArray).onElements("tr")

			.allowElements("track")
			.allowAttributes(trackAttributeArray).onElements("track")

			.allowElements("tt")

			.allowElements("u")
			.allowAttributes(mdnGlobalAttributeArray).onElements("u")

			.allowElements("ul")
			.allowAttributes(ulAttributeArray).onElements("ul")

			.allowElements("var")
			.allowAttributes(mdnGlobalAttributeArray).onElements("var")

			.allowElements("video")
			.allowAttributes(videoAttributeArray).onElements("video")

			.allowElements("wbr")
			.allowAttributes(mdnGlobalAttributeArray).onElements("wbr")

			.allowUrlProtocols("https", "http")
			.toFactory();
	}

	// todo
	public static PolicyFactory getDefaultPolicy() {
		if (instance == null) {
			instance = new NaverHtmlPolicy();
		}

		return NAVER_DEFAULT_POLICY;
	}

	public static PolicyFactory getExpandPolicy(PolicyFactory policyFactory) {
		return NaverHtmlPolicy.getDefaultPolicy().and(policyFactory);
	}


	// todo check array add
	private static String[] addAll(String[] array1, String[] array2) {
		String[] tempArr = new String[array1.length + array2.length];
		System.arraycopy(array1, 0, tempArr, 0, array1.length);
		System.arraycopy(array2, 0, tempArr, array1.length, array2.length);
		return tempArr;
	}
}