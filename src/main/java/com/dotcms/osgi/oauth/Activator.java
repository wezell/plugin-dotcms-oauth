package com.dotcms.osgi.oauth;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.osgi.framework.BundleContext;
import com.dotcms.filters.interceptor.FilterWebInterceptorProvider;
import com.dotcms.filters.interceptor.WebInterceptorDelegate;
import com.dotcms.osgi.oauth.interceptor.LoginRequiredOAuthInterceptor;
import com.dotcms.osgi.oauth.interceptor.LogoutOAuthInterceptor;
import com.dotcms.osgi.oauth.interceptor.OAuthCallbackInterceptor;
import com.dotcms.osgi.oauth.viewtool.OAuthToolInfo;
import com.dotmarketing.filters.AutoLoginFilter;
import com.dotmarketing.filters.LoginRequiredFilter;
import com.dotmarketing.loggers.Log4jUtil;
import com.dotmarketing.osgi.GenericBundleActivator;
import com.dotmarketing.util.Config;
import com.dotmarketing.util.Logger;

public class Activator extends GenericBundleActivator {

    private LoginRequiredOAuthInterceptor loginRequiredOAuthInterceptor = new LoginRequiredOAuthInterceptor();
    private OAuthCallbackInterceptor oAuthCallbackInterceptor = new OAuthCallbackInterceptor();
    private LogoutOAuthInterceptor logoutOAuthInterceptor = new LogoutOAuthInterceptor();

    private LoggerContext pluginLoggerContext;

    public void start(org.osgi.framework.BundleContext context) throws Exception {

        // Initializing log4j...
        final LoggerContext dotcmsLoggerContext = Log4jUtil.getLoggerContext();

        // Initialing the log4j context of this plugin based on the dotCMS logger context
        this.pluginLoggerContext = (LoggerContext) LogManager.getContext(this.getClass().getClassLoader(), false,
                        dotcmsLoggerContext, dotcmsLoggerContext.getConfigLocation());

        Logger.info(Activator.class.getName(), "Starting OSGi OAuth Interceptor");

        this.initializeServices(context);
        this.registerViewToolService(context, new OAuthToolInfo());

        final FilterWebInterceptorProvider filterWebInterceptorProvider =
                        FilterWebInterceptorProvider.getInstance(Config.CONTEXT);

        final WebInterceptorDelegate loginRequiredDelegate =
                        filterWebInterceptorProvider.getDelegate(LoginRequiredFilter.class);
        if (null != loginRequiredDelegate) {
            Logger.info(Activator.class.getName(), "Adding the LoginRequiredOAuthInterceptor");

            loginRequiredDelegate.addFirst(this.loginRequiredOAuthInterceptor);
        }

        final WebInterceptorDelegate autoLoginDelegate =
                        filterWebInterceptorProvider.getDelegate(AutoLoginFilter.class);
        if (null != autoLoginDelegate) {
            Logger.info(Activator.class.getName(), "Adding the LogoutOAuthInterceptor");

            autoLoginDelegate.addFirst(this.logoutOAuthInterceptor);

            Logger.info(Activator.class.getName(), "Adding the OAuthCallbackInterceptor");

            autoLoginDelegate.addFirst(this.oAuthCallbackInterceptor);
        }

    }

    @Override
    public void stop(BundleContext context) throws Exception {

        unregisterServices(context);

        final FilterWebInterceptorProvider filterWebInterceptorProvider =
                        FilterWebInterceptorProvider.getInstance(Config.CONTEXT);

        // Cleaning up the interceptors


        final WebInterceptorDelegate loginRequiredDelegate =
                        filterWebInterceptorProvider.getDelegate(LoginRequiredFilter.class);

        if (null != loginRequiredDelegate) {
            Logger.info(Activator.class.getName(), "Removing the LoginRequiredOAuthInterceptor");
            loginRequiredDelegate.remove(LoginRequiredOAuthInterceptor.class.getName(), true);
        }


        final WebInterceptorDelegate autoLoginDelegate =
                        filterWebInterceptorProvider.getDelegate(AutoLoginFilter.class);

        if (null != autoLoginDelegate) {
            Logger.info(Activator.class.getName(), "Removing the OAuthCallbackInterceptor");
            autoLoginDelegate.remove(OAuthCallbackInterceptor.class.getName(), true);
            Logger.info(Activator.class.getName(), "Removing the LogoutOAuthInterceptor");
            autoLoginDelegate.remove(LogoutOAuthInterceptor.class.getName(), true);
        }


        // Shutting down log4j in order to avoid memory leaks
        Log4jUtil.shutdown(pluginLoggerContext);
    }

}
