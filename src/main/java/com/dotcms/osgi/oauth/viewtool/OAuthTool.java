package com.dotcms.osgi.oauth.viewtool;

import com.dotcms.osgi.oauth.util.OAuthPropertyBundle;
import java.util.ArrayList;
import java.util.List;
import org.apache.velocity.tools.view.tools.ViewTool;

public class OAuthTool implements ViewTool {

	private final String NOTSET="xxxxxx";

	@Override
	public void init(Object initData) {
	}

	public List<String> getProviders() {

		java.util.List<String> providers = new ArrayList<>();

		String google = OAuthPropertyBundle.getProperty("Google20Api_API_KEY", NOTSET);
		String facebook = OAuthPropertyBundle.getProperty("Facebook20Api_API_KEY", NOTSET);
		String okta = OAuthPropertyBundle.getProperty("Okta20Api_API_KEY", NOTSET);
		String ping = OAuthPropertyBundle.getProperty("Ping20Api_API_KEY", NOTSET);

		if(!NOTSET.equals(google)){
			providers.add(google);
		}

		if(!NOTSET.equals(facebook)){
			providers.add(facebook);
		}

		if (!NOTSET.equals(okta)) {
			providers.add(okta);
		}

		if (!NOTSET.equals(ping)) {
			providers.add(ping);
		}

		return providers;
	}

}