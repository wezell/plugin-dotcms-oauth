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

		String google = OAuthPropertyBundle.getProperty("Google2Api_API_KEY", NOTSET);
		String facebook = OAuthPropertyBundle.getProperty("FacebookApi_API_KEY", NOTSET);
		String okta = OAuthPropertyBundle.getProperty("OktaApi20_API_KEY", NOTSET);

		if(!NOTSET.equals(google)){
			providers.add(google);
		}

		if(!NOTSET.equals(facebook)){
			providers.add(facebook);
		}

		if (!NOTSET.equals(okta)) {
			providers.add(okta);
		}

		return providers;
	}

}