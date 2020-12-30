package com.dotcms.osgi.oauth;

import org.osgi.framework.BundleContext;
import com.dotcms.filters.interceptor.FilterWebInterceptorProvider;
import com.dotcms.filters.interceptor.WebInterceptor;
import com.dotcms.filters.interceptor.WebInterceptorDelegate;
import com.dotcms.osgi.oauth.interceptor.LoginRequiredOAuthInterceptor;
import com.dotcms.osgi.oauth.interceptor.LogoutOAuthInterceptor;
import com.dotcms.osgi.oauth.interceptor.OAuthCallbackInterceptor;
import com.dotcms.osgi.oauth.viewtool.OAuthToolInfo;
import com.dotmarketing.filters.AutoLoginFilter;
import com.dotmarketing.osgi.GenericBundleActivator;
import com.dotmarketing.util.Config;
import com.dotmarketing.util.Logger;

public class Activator extends GenericBundleActivator {

    private WebInterceptor[] webInterceptors = {
                new LoginRequiredOAuthInterceptor(), 
                new OAuthCallbackInterceptor(), 
                new LogoutOAuthInterceptor()
            };


    final WebInterceptorDelegate delegate =
                    FilterWebInterceptorProvider.getInstance(Config.CONTEXT).getDelegate(AutoLoginFilter.class);

    public void start(org.osgi.framework.BundleContext context) throws Exception {


        Logger.info(Activator.class.getName(), "Starting OSGi OAuth Interceptor");

        this.initializeServices(context);
        this.registerViewToolService(context, new OAuthToolInfo());


        for (WebInterceptor webIn : webInterceptors) {
            Logger.info(Activator.class.getName(), "Adding the " + webIn.getName());
            delegate.addFirst(webIn);
        }

    }

    @Override
    public void stop(BundleContext context) throws Exception {

        unregisterServices(context);

        // Cleaning up the interceptors


        for (WebInterceptor webIn : webInterceptors) {
            Logger.info(Activator.class.getName(), "Removing the " + webIn.getName());
            delegate.remove(webIn.getClass().getName(), true);
        }

    }

}
