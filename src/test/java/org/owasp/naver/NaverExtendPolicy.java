package org.owasp.naver;

import com.google.common.collect.ImmutableSet;
import org.owasp.html.CssSchema;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.HtmlStreamEventReceiverWrapper;
import org.owasp.html.PolicyFactory;

public final class NaverExtendPolicy {

  private NaverExtendPolicy() {
  }

  public static PolicyFactory getExtendFactory() {
//		ImmutableSet<String> EXTEND_WHITELIST = ImmutableSet.of("bong-size");
    ImmutableSet<String> EXTEND_WHITELIST = ImmutableSet.of("bottom", "position");
    // CssSchema 아예 새로운거 추가가 안되나? => 안됌. 그리고 안되는게 맞는거지
    // todo 속성에 대한 값을 제어할 수 있는가 예를들어 style 에 position을 되게 했지만, position 의 relative 는 허용, absolute 는 막고 싶다.

    // todo CssSchema style 기존에 등록된걸 제거할 수 없는가?
    // todo style에서 가능한 key값과 가능한 value 값을 쉽게 볼 수 없나?

    CssSchema cssSchema = CssSchema.withProperties(EXTEND_WHITELIST);
    // 기존것에서 unoin 으로 append는 되는데, 기존것을 엎어치는건 안되나?
    return new HtmlPolicyBuilder()
            .allowAttributes("id").globally()
            .allowElements("span", "textarea")
            .allowAttributes("se2_tmp_te_border_style").onElements("span")
            .allowStyling(cssSchema)
            .withPreprocessor(
                    r -> new HtmlStreamEventReceiverWrapper(r) {
                      @Override
                      public void text(String s) {
                        System.out.println("lower!!");
                        underlying.text(s.toLowerCase());
                      }

                      @Override
                      public String toString() {
                        return "lower-text";
                      }
                    }
            )
            .toFactory();
  }
}
