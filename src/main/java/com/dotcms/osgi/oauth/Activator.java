package com.dotcms.osgi.oauth;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.osgi.framework.BundleContext;

import com.dotcms.filters.interceptor.FilterWebInterceptorProvider;
import com.dotcms.filters.interceptor.WebInterceptorDelegate;
import com.dotcms.osgi.oauth.util.OAuthPropertyBundle;
import com.dotcms.osgi.oauth.viewtool.OAuthToolInfo;
import com.dotmarketing.filters.AutoLoginFilter;
import com.dotmarketing.loggers.Log4jUtil;
import com.dotmarketing.osgi.GenericBundleActivator;
import com.dotmarketing.util.Config;
import com.dotmarketing.util.Logger;

public class Activator extends GenericBundleActivator {


  private org.apache.logging.log4j.core.LoggerContext pluginLoggerContext;



  @SuppressWarnings("unchecked")
  public void start(org.osgi.framework.BundleContext context) throws Exception {
    
 
    //Initializing log4j...
    final LoggerContext dotcmsLoggerContext = Log4jUtil.getLoggerContext();

    //Initialing the log4j context of this plugin based on the dotCMS logger context
    this.pluginLoggerContext = (LoggerContext) LogManager.getContext(this.getClass().getClassLoader(),
            false,
            dotcmsLoggerContext,
            dotcmsLoggerContext.getConfigLocation());

    Logger.info(this.getClass(), "Starting OSGi OAuth Filter");
    final String useFor = OAuthPropertyBundle.getProperty("USE_OAUTH_FOR","").toLowerCase();
    final boolean frontEnd = useFor.contains ("frontend");
    final boolean backEnd = useFor.contains ("backend");
    this.initializeServices(context);
    this.registerViewToolService(context, new OAuthToolInfo());
    
    final FilterWebInterceptorProvider filterWebInterceptorProvider = FilterWebInterceptorProvider.getInstance(Config.CONTEXT);
    final WebInterceptorDelegate delegate = filterWebInterceptorProvider.getDelegate(AutoLoginFilter.class);

    if (null != delegate) {
      System.out.println("Adding the OAuth2Interceptor");
      delegate.addFirst(new OAuth2Interceptor());
    }



  }

  @Override
  public void stop(BundleContext context) throws Exception {
    unregisterViewToolServices();
    final FilterWebInterceptorProvider filterWebInterceptorProvider = FilterWebInterceptorProvider.getInstance(Config.CONTEXT);
    final WebInterceptorDelegate delegate = filterWebInterceptorProvider.getDelegate(AutoLoginFilter.class);

    if (null != delegate) {
      System.out.println("Removing the ExampleAutoLoginWebInterceptor");
      delegate.remove(OAuth2Interceptor.class.getName(), true);
    }

  }


}
