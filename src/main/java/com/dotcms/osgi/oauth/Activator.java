package com.dotcms.osgi.oauth;

import java.util.ArrayList;
import java.util.List;

import org.apache.felix.http.api.ExtHttpService;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import org.osgi.util.tracker.ServiceTracker;
import org.tuckey.web.filters.urlrewrite.NormalRule;
import org.tuckey.web.filters.urlrewrite.Rule;

import com.dotmarketing.filters.CMSFilter;
import com.dotmarketing.filters.DotUrlRewriteFilter;
import com.dotmarketing.osgi.GenericBundleActivator;
import com.dotmarketing.util.Logger;

public class Activator extends GenericBundleActivator {

	private List<Rule> rules = new ArrayList<Rule>();
	private ExtHttpService httpService;
	private ServiceTracker serviceTracker;
	private OAuth2Servlet servlet;
	private final String OAUTH_URL = "/oauth2";

	@SuppressWarnings("unchecked")
	public void start(BundleContext context) throws Exception {

		serviceTracker = new ServiceTracker(context, OAuth2Servlet.class.getName(), null);

		// Initializing services...
		initializeServices(context);
		Logger.info(this.getClass(), "Starting OSGi OAuth Filter");
		ServiceReference sRef = context.getServiceReference(ExtHttpService.class.getName());
        if ( sRef != null ) {

        	serviceTracker.addingService( sRef );
            httpService = (ExtHttpService) context.getService( sRef );
            try {
                //Registering a simple test servlet
            	servlet = new OAuth2Servlet( serviceTracker );
                httpService.registerServlet( OAUTH_URL, servlet, null, null );

            } catch ( Exception e ) {
                e.printStackTrace();
            }
        }

		CMSFilter.addExclude("/app" + OAUTH_URL);

		// open service tracker to start tracking
		serviceTracker.open();

		NormalRule rule = new NormalRule();

		rule.setName("oauth-rule" + rules.size());
		rule.setFrom("^/dotCMS/login.*$");
		rule.setTo("/app" + OAUTH_URL);
		addRewriteRule(rule);
		rules.add(rule);
		
		
		rule = new NormalRule();
		rule.setName("oauth-rule" + rules.size());
		rule.setFrom("^/html/portal/login.*$");
		rule.setTo("/app" + OAUTH_URL + "?referrer=/c/portal/layout");
		addRewriteRule(rule);
		rules.add(rule);
		
		rule = new NormalRule();
		rule.setName("oauth-rule" + rules.size());
		rule.setFrom("^/c/portal_public/login.*$");
		rule.setTo("/app" + OAUTH_URL + "?referrer=/c/portal/layout");
		addRewriteRule(rule);
		rules.add(rule);
		
		rule = new NormalRule();
		rule.setName("oauth-rule" + rules.size());
		rule.setFrom("^/c/portal/logout.*$");
		rule.setTo("/c/portal/logout?referer=/");
		addRewriteRule(rule);
		rules.add(rule);
		
		
		Logger.info(this.getClass(), "We now have " + DotUrlRewriteFilter.getUrlRewriteFilter().getRules().size() + " rules");

	}

	public void stop(BundleContext context) throws Exception {
        //Unregister the servlet
        if ( httpService != null && servlet != null ) {
            httpService.unregisterServlet( servlet );
        }
		CMSFilter.removeExclude("/app" + OAUTH_URL);
		Logger.info(this.getClass(), "Removing OSGi OAuth Servlet");
		for(Rule rule : rules){

			
			DotUrlRewriteFilter.getUrlRewriteFilter().removeRule(rule);
		}
		Logger.info(this.getClass(), "We now have " + DotUrlRewriteFilter.getUrlRewriteFilter().getRules().size() + " rules");
		// close service tracker to stop tracking
		serviceTracker.close();

	}

}