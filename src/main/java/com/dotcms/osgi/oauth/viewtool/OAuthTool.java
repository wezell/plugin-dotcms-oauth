package com.dotcms.osgi.oauth.viewtool;
import java.util.ArrayList;
import java.util.List;

import org.apache.velocity.tools.view.tools.ViewTool;

import com.dotcms.osgi.oauth.util.OAuthPropertyBundle;

public class OAuthTool implements ViewTool {

	private final String NOTSET="xxxxxx";
	@Override
	public void init(Object initData) {
	}

	public List<String> getProviders() {

		java.util.List<String> providers = new ArrayList<String>();
		
		
		String google = OAuthPropertyBundle.getProperty("Google2Api_API_KEY", NOTSET);
		String facebook = OAuthPropertyBundle.getProperty("FacebookApi_API_KEY", NOTSET);
		if(!NOTSET.equals(google)){
			providers.add(google);
			
		}
		if(!NOTSET.equals(facebook)){
			providers.add(facebook);
			
		}
		return providers;
		
		
		
		
	}



}
