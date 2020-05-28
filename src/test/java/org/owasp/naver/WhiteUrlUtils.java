package org.owasp.naver;

import com.google.common.base.Predicate;

import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class WhiteUrlUtils {

  public static List<Pattern> convertToPatternList(List<String> whiteUrlList) {
    List<Pattern> whiteUrlPatternList = new ArrayList<>(whiteUrlList.size());
    for (String eachWhiteUrl : whiteUrlList) {
      Pattern pattern = buildPattern(eachWhiteUrl);
      whiteUrlPatternList.add(pattern);
    }

    return whiteUrlPatternList;
  }

  public static Predicate<String> predicate(List<Pattern> whiteUrlPatternList) {
    return url -> {
      if (url == null || url.isEmpty()) {
        return false;
      }

      if (whiteUrlPatternList == null || whiteUrlPatternList.isEmpty()) {
        return false;
      }

      for (Pattern eachWhiteUrlPattern : whiteUrlPatternList) {
        if (eachWhiteUrlPattern.matcher(url).matches()) {
          return true;
        }
      }

      return false;
    };
  }

  private static Pattern buildPattern(String raw) {
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
}
