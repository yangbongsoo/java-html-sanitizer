package org.owasp.naver;

import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;

public class NaverHtmlPolicy {

	// exclude attribute : translate, contenteditable, data-*, draggable, dropzone, spellcheck
//	private String[] w3schoolsGlobalAttributeArray = {"accesskey", "class", "dir", "hidden", "id", "lang", "tabindex", "title", "style"};

	// exclude attribute : autocapitalize contenteditable contextmenu data-* draggable dropzone inputmode is itemid itemprop itemref itemscope itemtype part slot spellcheck translate
	private String[] mdnGlobalAttributeArray = {"accesskey", "class", "dir", "exportparts", "hidden", "id", "lang", "style", "tabindex", "title"};

	// MDN doesn't have media attribute (but w3schools have)
	private String[] aDefaultAttributeArray = {"charset", "coords", "href", "hreflang", "media", "name", "rel", "rev", "shape", "target", "type"};
	private String[] appletDefaultAttributeArray = {"code", "object", "align", "alt", "archive", "codebase", "height", "hspace", "name", "vspace", "width"};

	// exclude attribute : download
	private String[] areaDefaultAttributeArray = {"alt", "coords", "href", "hreflang", "media", "nohref", "rel", "shape", "target", "type"};
	private String[] audioDefaultAttributeArray = {"autoplay", "controls", "loop", "muted", "preload", "src"};
	private String[] basefontDefaultAttributeArray = {"color", "face", "size"};
	private String[] blockquoteDefaultAttributeArray = {"cite"};

	// exclude attribute : formaction
	private String[] buttonDefaultAttributeArray = {"autofocus", "disabled", "form", "formenctype", "formmethod", "formnovalidate", "formtarget", "name", "type", "value"};
	private String[] canvasDefaultAttributeArray = {"height", "width"};
	private String[] captionDefaultAttributeArray = {"align"};
	private String[] colDefaultAttributeArray = {"align", "char", "charoff", "span", "valign", "width"};
	private String[] colgroupDefaultAttributeArray = {"align", "char", "charoff", "span", "valign", "width"};
	private String[] commandDefaultAttributeArray = {"type"};
	private String[] delDefaultAttributeArray = {"cite", "datetime"};
	private String[] detailsDefaultAttributeArray = {"open"};
	private String[] dirDefaultAttributeArray = {"compact"};
	private String[] divDefaultAttributeArray = {"align"};
	private String[] fieldsetDefaultAttributeArray = {"disabled", "form", "name"};
	private String[] fontDefaultAttributeArray = {"color", "face", "size"};
	private String[] formDefaultAttributeArray = {"accept", "accept-charset", "action", "autocomplete", "enctype", "method", "name", "novalidate", "target"};
	private String[] frameDefaultAttributeArray = {"frameborder", "longdesc", "marginheight", "marginwidth", "name", "noresize", "scrolling", "src"};
	private String[] framesetDefaultAttributeArray = {"cols", "rows"};
	private String[] h1Toh6DefaultAttributeArray = {"align"};
	private String[] headDefaultAttributeArray = {"profile"};
	private String[] hrDefaultAttributeArray = {"align", "noshade", "size", "width"};

	// exclude attribute : crossorigin, srcset
	private String[] imgDefaultAttributeArray = {"align", "alt", "border", "height", "hspace", "ismap", "longdesc", "sizes", "src", "usemap", "vspace", "width"};

	// exclude attribute : dirname, formaction
	private String[] inputDefaultAttributeArray = {"accept", "align", "alt", "autocomplete", "autofocus", "checked", "disabled", "form", "formenctype", "formmethod",
		"formnovalidate", "formtarget", "height", "list", "max", "maxlength", "min", "multiple", "name", "pattern", "placeholder", "readonly", "required", "size",
		"src", "step", "type", "value", "width"};

	private String[] insDefaultAttributeArray = {"cite", "datetime"};
	private String[] isindexDefaultAttributeArray = {"action", "prompt"};
	private String[] keygenDefaultAttributeArray = {"autofocus", "challenge", "disabled", "form", "keytype", "name"};
	private String[] labelDefaultAttributeArray = {"for", "form"};
	private String[] legendDefaultAttributeArray = {"align"};
	private String[] liDefaultAttributeArray = {"type", "value"};
	private String[] mapDefaultAttributeArray = {"name"};
	private String[] marqueeDefaultAttributeArray = {"width", "height", "direction", "behavior", "scrolldelay", "scrollamount", "bgcolor", "hspace", "vspace", "loop"};
	private String[] menuDefaultAttributeArray = {"type", "id"};
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
		// del
		String[] delAttributeArray = addAll(delDefaultAttributeArray, mdnGlobalAttributeArray);
		// details
		String[] detailsAttributeArray = addAll(detailsDefaultAttributeArray, mdnGlobalAttributeArray);
		// div
		String[] divAttributeArray = addAll(divDefaultAttributeArray, mdnGlobalAttributeArray);
		// fieldset
		String[] fieldsetAttributeArray = addAll(fieldsetDefaultAttributeArray, mdnGlobalAttributeArray);
		// form
		String[] formAttributeArray = addAll(formDefaultAttributeArray, mdnGlobalAttributeArray);
		// h1 - h6
		String[] h1Toh6AttributeArray = addAll(h1Toh6DefaultAttributeArray, mdnGlobalAttributeArray);
		// head
		String[] headAttributeArray = addAll(headDefaultAttributeArray, mdnGlobalAttributeArray);
		// hr
		String[] hrAttributeArray = addAll(hrDefaultAttributeArray, mdnGlobalAttributeArray);
		// img
		String[] imgAttributeArray = addAll(imgDefaultAttributeArray, mdnGlobalAttributeArray);
		// input
		String[] inputAttributeArray = addAll(inputDefaultAttributeArray, mdnGlobalAttributeArray);
		// ins
		String[] insAttributeArray = addAll(insDefaultAttributeArray, mdnGlobalAttributeArray);
		// keygen
		String[] keygenAttributeArray = addAll(keygenDefaultAttributeArray, mdnGlobalAttributeArray);
		// label
		String[] labelAttributeArray = addAll(labelDefaultAttributeArray, mdnGlobalAttributeArray);
		// legend
		String[] legendAttributeArray = addAll(legendDefaultAttributeArray, mdnGlobalAttributeArray);
		// li
		String[] liAttributeArray = addAll(liDefaultAttributeArray, mdnGlobalAttributeArray);
		// map
		String[] mapAttributeArray = addAll(mapDefaultAttributeArray, mdnGlobalAttributeArray);
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

			.allowElements("adress")
			.allowAttributes(mdnGlobalAttributeArray).onElements("adress")

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

			// base(exclude element)

			.allowElements("basefont")
			.allowAttributes(basefontDefaultAttributeArray).onElements("basefont")

			.allowElements("bdi")
			.allowAttributes(mdnGlobalAttributeArray).onElements("bdi")

			.allowElements("bdo")
			.allowAttributes(mdnGlobalAttributeArray).onElements("bdo")

			.allowElements("big")

			.allowElements("blockquote")
			.allowAttributes(blockquoteAttributeArray).onElements("blockquote")

			// body(exclude element)

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
			.allowAttributes(commandDefaultAttributeArray).onElements("command")

			// data element(exclude element)

			.allowElements("datalist")
			.allowAttributes(mdnGlobalAttributeArray).onElements("datalist")

			.allowElements("dd")
			.allowAttributes(mdnGlobalAttributeArray).onElements("dd")

			.allowElements("del")
			.allowAttributes(delAttributeArray).onElements("del")

			.allowElements("details")
			.allowAttributes(detailsAttributeArray).onElements("details")

			.allowElements("dfn")
			.allowAttributes(mdnGlobalAttributeArray).onElements("dfn")

			// dialog(exclude element)

			.allowElements("dir")
			.allowAttributes(dirDefaultAttributeArray).onElements("dir")

			.allowElements("div")
			.allowAttributes(divAttributeArray).onElements("div")

			.allowElements("dl")
			.allowAttributes(mdnGlobalAttributeArray).onElements("dl")

			.allowElements("dt")
			.allowAttributes(mdnGlobalAttributeArray).onElements("dt")

			.allowElements("em")
			.allowAttributes(mdnGlobalAttributeArray).onElements("em")

			// embed(exclude element)

			.allowElements("fieldset")
			.allowAttributes(fieldsetAttributeArray).onElements("fieldset")

			.allowElements("figcaption")
			.allowAttributes(mdnGlobalAttributeArray).onElements("figcaption")

			.allowElements("figure")
			.allowAttributes(mdnGlobalAttributeArray).onElements("figure")

			.allowElements("font")
			.allowAttributes(fontDefaultAttributeArray).onElements("font")

			.allowElements("footer")
			.allowAttributes(mdnGlobalAttributeArray).onElements("footer")

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
			.allowAttributes(mdnGlobalAttributeArray).onElements("header")

			.allowElements("hgroup")
			.allowAttributes(mdnGlobalAttributeArray).onElements("hgroup")

			.allowElements("hr")
			.allowAttributes(hrAttributeArray).onElements("hr")

			.allowElements("html") // xmlns(exclude attribute)
			.allowAttributes(mdnGlobalAttributeArray).onElements("html")

			.allowElements("i")
			.allowAttributes(mdnGlobalAttributeArray).onElements("i")

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
			.allowAttributes(mdnGlobalAttributeArray).onElements("kbd")

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
			.allowAttributes(mdnGlobalAttributeArray).onElements("mark")

			// meta(exclude element)

			// nobr(exclude element) https://developer.mozilla.org/en-US/docs/Web/HTML/Element/nobr

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