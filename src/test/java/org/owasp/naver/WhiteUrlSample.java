package org.owasp.naver;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class WhiteUrlSample { // naver cafe sample
	public static final List<String> A_HREF_WHITE_URL_LIST = Collections.unmodifiableList(Arrays.asList(
			"http://serviceapi.nmv.naver.com*",
			"http://scrap.ad.naver.com*",
			"http://test-player.naver.com/naverPlayer/posting*",
			"http://alpha-player.naver.com/naverPlayer/posting*",
			"http://beta-player.naver.com/naverPlayer/posting*",
			"http://musicplayer.naver.com/naverPlayer/posting*",
			"http://player.music.naver.com/naverPlayer/posting*",
			"http://dev.player.music.naver.com*",
			"http://test.player.music.naver.com*",
			"http://qa.player.music.naver.com*",
			"http://staging.player.music.naver.com*",
			"http://alpha.player.music.naver.com*",
			"http://beta.player.music.naver.com*",
			"http://stage.player.music.naver.com*"
	));
}
