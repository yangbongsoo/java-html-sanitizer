package org.owasp.naver;

import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import com.google.common.base.Predicate;

public class WhiteUrlUtils {
	public static Pattern buildPattern(String raw) {
		StringWriter writer = new StringWriter();
		writer.write("['\"]?\\s*(?i:");

		int pos = 0;
		int length = raw.length();
		for (int i = 0; i < raw.length(); i++) {
			char c = raw.charAt(i);
			switch (c) {
				case '\\':
				case '+':
				case '{':
				case '}':
				case '[':
				case ']':
				case '^':
				case '$':
				case '&':
				case '.':
				case '?':
				case '(':
				case ')':
				case '*':
					if (i > pos) {
						writer.write(raw, pos, i - pos);
					}

					if (c == '*') {
						writer.write(".*");
					} else {
						writer.write("\\");
						writer.write(c);
					}
					pos = i + 1;
					break;
			}
		}

		if (length > pos) {
			writer.write(raw, pos, length - pos);
		}

		writer.write(")\\s*['\"]?");

		return Pattern.compile(writer.toString());
	}

	public static Predicate<String> predicate(List<String> whiteUrlList) {
		 return url -> {
			if (url == null || url.isEmpty()) {
				return false;
			}

			if (whiteUrlList == null || whiteUrlList.isEmpty()) {
				return false;
			}

			// todo Pattern으로 만드는 작업을 항상 수행할 필요가 없는데 ...
			 List<Pattern> patterns = new ArrayList<>();
			 for (String eachWhiteUrl : whiteUrlList) {
				 Pattern pattern = buildPattern(eachWhiteUrl);
				 patterns.add(pattern);
			 }

			for (Pattern pattern : patterns) {
				if (pattern.matcher(url).matches()) {
					return true;
				}
			}

			return false;
		};
	}
}
