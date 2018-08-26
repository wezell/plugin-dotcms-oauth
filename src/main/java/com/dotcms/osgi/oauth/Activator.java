package com.dotcms.osgi.oauth;

import com.dotcms.filters.interceptor.FilterWebInterceptorProvider;
import com.dotcms.filters.interceptor.WebInterceptorDelegate;
import com.dotcms.osgi.oauth.interceptor.AutoLoginOAuthInterceptor;
import com.dotcms.osgi.oauth.interceptor.LoginRequiredOAuthInterceptor;
import com.dotcms.osgi.oauth.viewtool.OAuthToolInfo;
import com.dotmarketing.filters.AutoLoginFilter;
import com.dotmarketing.filters.LoginRequiredFilter;
import com.dotmarketing.loggers.Log4jUtil;
import com.dotmarketing.osgi.GenericBundleActivator;
import com.dotmarketing.util.Config;
import com.dotmarketing.util.Logger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.osgi.framework.BundleContext;

public class Activator extends GenericBundleActivator {

    private LoginRequiredOAuthInterceptor loginRequiredOAuthInterceptor;
    private AutoLoginOAuthInterceptor autoLoginOAuthInterceptor;

    private LoggerContext pluginLoggerContext;

    @SuppressWarnings("unchecked")
    public void start(org.osgi.framework.BundleContext context) throws Exception {

        //Initializing log4j...
        final LoggerContext dotcmsLoggerContext = Log4jUtil.getLoggerContext();

        //Initialing the log4j context of this plugin based on the dotCMS logger context
        this.pluginLoggerContext = (LoggerContext) LogManager
                .getContext(this.getClass().getClassLoader(),
                        false,
                        dotcmsLoggerContext,
                        dotcmsLoggerContext.getConfigLocation());

        Logger.info(this.getClass(), "Starting OSGi OAuth Filter");

        this.initializeServices(context);
        this.registerViewToolService(context, new OAuthToolInfo());

        final FilterWebInterceptorProvider filterWebInterceptorProvider = FilterWebInterceptorProvider
                .getInstance(Config.CONTEXT);

        final WebInterceptorDelegate loginRequiredDelegate = filterWebInterceptorProvider
                .getDelegate(LoginRequiredFilter.class);
        if (null != loginRequiredDelegate) {
            System.out.println("Adding the LoginRequiredOAuthInterceptor");
            this.loginRequiredOAuthInterceptor = new LoginRequiredOAuthInterceptor();
            loginRequiredDelegate.addFirst(this.loginRequiredOAuthInterceptor);
        }

        final WebInterceptorDelegate autoLoginDelegate = filterWebInterceptorProvider
                .getDelegate(AutoLoginFilter.class);
        if (null != autoLoginDelegate) {
            System.out.println("Adding the OAuth2Interceptor");
            this.autoLoginOAuthInterceptor = new AutoLoginOAuthInterceptor();
            autoLoginDelegate.addFirst(this.autoLoginOAuthInterceptor);
        }

    }

    @Override
    public void stop(BundleContext context) throws Exception {

        unregisterServices(context);

        final FilterWebInterceptorProvider filterWebInterceptorProvider = FilterWebInterceptorProvider
                .getInstance(Config.CONTEXT);

        // Cleaning up the interceptors

        if (null != this.loginRequiredOAuthInterceptor) {
            final WebInterceptorDelegate loginRequiredDelegate = filterWebInterceptorProvider
                    .getDelegate(LoginRequiredFilter.class);

            if (null != loginRequiredDelegate) {
                System.out.println("Removing the BackEndLoginRequiredOAuthInterceptor");
                loginRequiredDelegate.remove(this.loginRequiredOAuthInterceptor.getName(), true);
            }
        }

        if (null != this.autoLoginOAuthInterceptor) {
            final WebInterceptorDelegate autoLoginDelegate = filterWebInterceptorProvider
                    .getDelegate(AutoLoginFilter.class);

            if (null != autoLoginDelegate) {
                System.out.println("Removing the OAuth2Interceptor");
                autoLoginDelegate.remove(AutoLoginOAuthInterceptor.class.getName(), true);
            }
        }

        //Shutting down log4j in order to avoid memory leaks
        Log4jUtil.shutdown(pluginLoggerContext);
    }

}