package org.owasp.html;

import com.google.common.collect.ImmutableSet;
import junit.framework.TestCase;
import org.junit.Test;

public class AllowDisAllowElementsTest extends TestCase {

  // beforePolicy : X
  // newPolicy : X
  @Test
  public void testAllowElements1() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .toFactory();

    String input = "<p>pText</p>\n<b>bText</b>\n<i>iText</i>";
    assertEquals("pText\nbText\niText", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("pText\nbText\niText", afterPolicy.sanitize(input));
  }

  // beforePolicy : X
  // newPolicy : allow
  @Test
  public void testAllowElements2() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .toFactory();

    String input = "<p>pText</p>\n<b>bText</b>\n<i>iText</i>";
    assertEquals("pText\nbText\niText", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .allowElements("p","b", "i")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("<p>pText</p>\n<b>bText</b>\n<i>iText</i>", afterPolicy.sanitize(input));
  }

  // beforePolicy : X
  // newPolicy : allow
  @Test
  public void testAllowElements2_1() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .toFactory();

    String input = "<p>pText</p>\n<b>bText</b>\n<i>iText</i>";
    assertEquals("pText\nbText\niText", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .allowElements("p","b")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("<p>pText</p>\n<b>bText</b>\niText", afterPolicy.sanitize(input));
  }

  // beforePolicy : X
  // newPolicy : allow
  @Test
  public void testAllowElements2_2() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .toFactory();

    String input = "<p>pText</p>\n<b>bText</b>\n<i>iText</i>";
    assertEquals("pText\nbText\niText", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .allowElements("p","b")
            .disallowElements("b")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("<p>pText</p>\nbText\niText", afterPolicy.sanitize(input));
  }

  // beforePolicy : X
  // newPolicy : allow
  @Test
  public void testAllowElements2_3() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .toFactory();

    String input = "<p>pText</p>\n<b>bText</b>\n<i>iText</i>";
    assertEquals("pText\nbText\niText", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .allowElements("p","b")
            .disallowElements("p", "b")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("pText\nbText\niText", afterPolicy.sanitize(input));
  }

  // beforePolicy : X
  // newPolicy : allow
  @Test
  public void testAllowElements2_4() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .toFactory();

    String input = "<p>pText</p>\n<b>bText</b>\n<i>iText</i>";
    assertEquals("pText\nbText\niText", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .allowElements("p","b")
            .disallowElements("")
            .allowElements("i")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("<p>pText</p>\n<b>bText</b>\n<i>iText</i>", afterPolicy.sanitize(input));
  }

  // beforePolicy : X
  // newPolicy : disallow
  @Test
  public void testAllowElements3() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .toFactory();

    String input = "<p>pText</p>\n<b>bText</b>\n<i>iText</i>";
    assertEquals("pText\nbText\niText", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .disallowElements("p","b", "i")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("pText\nbText\niText", afterPolicy.sanitize(input));
  }

  // beforePolicy : X
  // newPolicy : disallow
  @Test
  public void testAllowElements3_1() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .toFactory();

    String input = "<p>pText</p>\n<b>bText</b>\n<i>iText</i>";
    assertEquals("pText\nbText\niText", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .disallowElements("p", "i")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("pText\nbText\niText", afterPolicy.sanitize(input));
  }

  // beforePolicy : X
  // newPolicy : disallow
  @Test
  public void testAllowElements3_2() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .toFactory();

    String input = "<p>pText</p>\n<b>bText</b>\n<i>iText</i>";
    assertEquals("pText\nbText\niText", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .allowElements("a")
            .disallowElements("p", "i")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("pText\nbText\niText", afterPolicy.sanitize(input));
  }

  // beforePolicy : allow
  // newPolicy : X
  @Test
  public void testAllowElements4() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("p", "b", "i")
            .toFactory();

    String input = "<p>pText</p>\n<b>bText</b>\n<i>iText</i>";
    assertEquals("<p>pText</p>\n<b>bText</b>\n<i>iText</i>", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("<p>pText</p>\n<b>bText</b>\n<i>iText</i>", afterPolicy.sanitize(input));
  }

  // beforePolicy : allow
  // newPolicy : X
  @Test
  public void testAllowElements4_1() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("p", "b")
            .toFactory();

    String input = "<p>pText</p>\n<b>bText</b>\n<i>iText</i>";
    assertEquals("<p>pText</p>\n<b>bText</b>\niText", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("<p>pText</p>\n<b>bText</b>\niText", afterPolicy.sanitize(input));
  }

  // beforePolicy : allow
  // newPolicy : allow
  @Test
  public void testAllowElements5() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("p", "b", "i")
            .toFactory();

    String input = "<p>pText</p>\n<b>bText</b>\n<i>iText</i>";
    assertEquals("<p>pText</p>\n<b>bText</b>\n<i>iText</i>", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .allowElements("p", "b", "i")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("<p>pText</p>\n<b>bText</b>\n<i>iText</i>", afterPolicy.sanitize(input));
  }

  // beforePolicy : allow
  // newPolicy : allow
  @Test
  public void testAllowElements5_1() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("p", "b")
            .toFactory();

    String input = "<p>pText</p>\n<b>bText</b>\n<i>iText</i>";
    assertEquals("<p>pText</p>\n<b>bText</b>\niText", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .allowElements("i")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("<p>pText</p>\n<b>bText</b>\n<i>iText</i>", afterPolicy.sanitize(input));
  }

  // beforePolicy : allow
  // newPolicy : allow
  @Test
  public void testAllowElements5_2() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("p", "b")
            .toFactory();

    String input = "<p>pText</p>\n<b>bText</b>\n<i>iText</i>\n<s>sText</s>";
    assertEquals("<p>pText</p>\n<b>bText</b>\niText\nsText", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .allowElements("s")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("<p>pText</p>\n<b>bText</b>\niText\n<s>sText</s>", afterPolicy.sanitize(input));
  }

  // beforePolicy : allow
  // newPolicy : disallow
  @Test
  public void testAllowElements6() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("p")
            .toFactory();

    String input = "<p>pText</p>";
    assertEquals("<p>pText</p>", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .disallowElements("p")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("pText", afterPolicy.sanitize(input));
  }


  // beforePolicy : allow
  // newPolicy : disallow
  @Test
  public void testAllowElements6_1() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("p", "b")
            .toFactory();

    String input = "<p>pText</p>\n<b>bText</b>\n<i>iText</i>\n<s>sText</s>";
    assertEquals("<p>pText</p>\n<b>bText</b>\niText\nsText", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .disallowElements("p")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("pText\n<b>bText</b>\niText\nsText", afterPolicy.sanitize(input));
  }

  // beforePolicy : allow
  // newPolicy : disallow
  @Test
  public void testAllowElements6_2() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("p", "b", "i", "s")
            .toFactory();

    String input = "<p>pText</p>\n<b>bText</b>\n<i>iText</i>\n<s>sText</s>";
    assertEquals("<p>pText</p>\n<b>bText</b>\n<i>iText</i>\n<s>sText</s>", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .disallowElements("p", "p", "b", "b")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("pText\nbText\n<i>iText</i>\n<s>sText</s>", afterPolicy.sanitize(input));
  }

  // beforePolicy : allow
  // newPolicy : disallow
  // new2Policy : allow
  @Test
  public void testAllowElements6_3() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("p", "b", "i", "s")
            .toFactory();

    String input = "<p>pText</p>\n<b>bText</b>\n<i>iText</i>\n<s>sText</s>";
    assertEquals("<p>pText</p>\n<b>bText</b>\n<i>iText</i>\n<s>sText</s>", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .disallowElements("p", "p", "b", "b")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("pText\nbText\n<i>iText</i>\n<s>sText</s>", afterPolicy.sanitize(input));

    PolicyFactory new2Policy = new HtmlPolicyBuilder()
            .allowElements("p", "b")
            .toFactory();

    PolicyFactory after2Policy = afterPolicy.and(new2Policy);
    assertEquals("<p>pText</p>\n<b>bText</b>\n<i>iText</i>\n<s>sText</s>", after2Policy.sanitize(input));
  }

  // beforePolicy : allow
  // newPolicy : disallow
  // new2Policy : disallow
  @Test
  public void testAllowElements6_4() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("p", "b", "i", "s")
            .toFactory();

    String input = "<p>pText</p>\n<b>bText</b>\n<i>iText</i>\n<s>sText</s>";
    assertEquals("<p>pText</p>\n<b>bText</b>\n<i>iText</i>\n<s>sText</s>", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .disallowElements("p", "p", "b", "b")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("pText\nbText\n<i>iText</i>\n<s>sText</s>", afterPolicy.sanitize(input));

    PolicyFactory new2Policy = new HtmlPolicyBuilder()
            .disallowElements("i", "s")
            .toFactory();

    PolicyFactory after2Policy = afterPolicy.and(new2Policy);
    assertEquals("pText\nbText\niText\nsText", after2Policy.sanitize(input));
  }

  // beforePolicy : allow
  // newPolicy : disallow
  // new2Policy : X
  @Test
  public void testAllowElements6_5() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("p", "b", "i", "s")
            .toFactory();

    String input = "<p>pText</p>\n<b>bText</b>\n<i>iText</i>\n<s>sText</s>";
    assertEquals("<p>pText</p>\n<b>bText</b>\n<i>iText</i>\n<s>sText</s>", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .disallowElements("p", "p", "b", "b")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("pText\nbText\n<i>iText</i>\n<s>sText</s>", afterPolicy.sanitize(input));

    PolicyFactory new2Policy = new HtmlPolicyBuilder()
            .toFactory();

    PolicyFactory after2Policy = afterPolicy.and(new2Policy);
    assertEquals("pText\nbText\n<i>iText</i>\n<s>sText</s>", after2Policy.sanitize(input));
  }

  // beforePolicy : disallow
  // newPolicy : X
  @Test
  public void testAllowElements7() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .disallowElements("p", "b")
            .toFactory();

    String input = "<p>pText</p>\n<b>bText</b>\n<i>iText</i>\n<s>sText</s>";
    assertEquals("pText\nbText\niText\nsText", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("pText\nbText\niText\nsText", afterPolicy.sanitize(input));
  }

  // beforePolicy : disallow
  // newPolicy : allow
  @Test
  public void testAllowElements8() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .disallowElements("p", "b")
            .toFactory();

    String input = "<p>pText</p>\n<b>bText</b>\n<i>iText</i>\n<s>sText</s>";
    assertEquals("pText\nbText\niText\nsText", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .allowElements("p", "b")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("<p>pText</p>\n<b>bText</b>\niText\nsText", afterPolicy.sanitize(input));
  }

  // beforePolicy : disallow
  // newPolicy : allow
  @Test
  public void testAllowElements8_1() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .disallowElements("p", "b")
            .toFactory();

    String input = "<p>pText</p>\n<b>bText</b>\n<i>iText</i>\n<s>sText</s>";
    assertEquals("pText\nbText\niText\nsText", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .allowElements("p")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("<p>pText</p>\nbText\niText\nsText", afterPolicy.sanitize(input));
  }

  // beforePolicy : disallow
  // newPolicy : allow
  @Test
  public void testAllowElements8_2() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .disallowElements("p", "b")
            .toFactory();

    String input = "<p>pText</p>\n<b>bText</b>\n<i>iText</i>\n<s>sText</s>";
    assertEquals("pText\nbText\niText\nsText", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .allowElements("p", "i", "s")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("<p>pText</p>\nbText\n<i>iText</i>\n<s>sText</s>", afterPolicy.sanitize(input));
  }

  // beforePolicy : disallow
  // newPolicy : disallow
  @Test
  public void testAllowElements9() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .disallowElements("p", "b")
            .toFactory();

    String input = "<p>pText</p>\n<b>bText</b>\n<i>iText</i>\n<s>sText</s>";
    assertEquals("pText\nbText\niText\nsText", beforePolicy.sanitize(input));

    PolicyFactory newPolicy = new HtmlPolicyBuilder()
            .disallowElements("i", "s")
            .toFactory();

    PolicyFactory afterPolicy = beforePolicy.and(newPolicy);

    assertEquals("pText\nbText\niText\nsText", afterPolicy.sanitize(input));
  }
}
