/*
 * WebSessionFilter
 *
 * A filter that recognizes return users who have chosen to have their login information remembered.
 * Creates a valid WebSession object and passes it a contact to use to fill its information
 *
 */
package com.dotcms.osgi.oauth.interceptor;

import static com.dotcms.osgi.oauth.util.Constants.OAUTH_API_PROVIDER;
import static com.dotcms.osgi.oauth.util.Constants.OAUTH_PROVIDER;
import static com.dotcms.osgi.oauth.util.Constants.OAUTH_REDIRECT;
import static com.dotcms.osgi.oauth.util.Constants.OAUTH_SERVICE;
import static com.dotcms.osgi.oauth.util.OAuthPropertyBundle.getProperty;
import java.io.IOException;
import java.util.Optional;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.scribe.builder.api.DefaultApi20;
import org.scribe.model.OAuthConstants;
import org.scribe.oauth.OAuthService;
import com.dotcms.filters.interceptor.Result;
import com.dotcms.filters.interceptor.WebInterceptor;
import com.dotcms.osgi.oauth.app.AppConfig;
import com.dotcms.osgi.oauth.util.Constants;
import com.dotcms.osgi.oauth.util.OauthUtils;
import com.dotmarketing.business.APILocator;
import com.dotmarketing.util.Logger;
import com.liferay.portal.model.User;
import io.vavr.control.Try;

public class OAuthCallbackInterceptor implements WebInterceptor {

    public static final String CALLBACK_URL = "/api/v1/oauth2/callback";

    private final User systemUser;

    public OAuthCallbackInterceptor() {


        this.systemUser = APILocator.systemUser();
    }

    @Override
    public String[] getFilters() {
        return new String[] {CALLBACK_URL};
    }


    @Override
    public Result intercept(HttpServletRequest request, HttpServletResponse response) {

        // If we already have a logged in user, continue
        boolean isLoggedInUser = APILocator.getLoginServiceAPI().isLoggedIn(request);
        if (isLoggedInUser) {
            return Result.NEXT;
        }


        Optional<AppConfig> config = AppConfig.config(request);
        final String requestedURI = request.getRequestURI();

        // if we have no oauth configured, continue
        if (!config.isPresent()) {
            return Result.NEXT;
        }

        final String responseCode = request.getParameter(OAuthConstants.CODE);
        if (null == responseCode) {
            Logger.info(this.getClass().getName(), "No Response Code param found, continuing");
            return Result.NEXT;
        }

        Logger.info(this.getClass().getName(), "Code param found, doing callback");
        try {

            final OAuthService oAuthService = (OAuthService) request.getSession().getAttribute(OAUTH_SERVICE);
            final DefaultApi20 apiProvider = (DefaultApi20) request.getSession().getAttribute(OAUTH_API_PROVIDER);

            final String providerName = apiProvider.getClass().getSimpleName();

            // With the authentication code lets try to authenticate to dotCMS
            OauthUtils.getInstance().authenticate(request, response, oAuthService);

            HttpSession session = request.getSession(true);


            // redirect onward!
            final String authorizationUrl = (String) session.getAttribute(OAUTH_REDIRECT);
            session.removeAttribute(OAUTH_REDIRECT);
            session.removeAttribute(OAUTH_SERVICE);
            session.setAttribute(OAUTH_PROVIDER, apiProvider.getClass().getCanonicalName());
            if (authorizationUrl == null) {
                return this.redirectLoggedInUser(request, response);
                
            }

            
            
            
            response.sendRedirect(authorizationUrl);
            return Result.SKIP_NO_CHAIN; // needs to stop the filter chain.

        } catch (Exception e) {
            Logger.error(this.getClass().getName(), e.getMessage(), e);
        }


        Try.run(() -> response.sendError(403));
        return Result.SKIP_NO_CHAIN;
    }



    private Result redirectLoggedInUser(HttpServletRequest request, HttpServletResponse response) throws IOException {

        if (request.getSession().getAttribute(Constants.FRONT_END_LOGIN) != null) {
            Logger.info(this.getClass().getName(), "Already logged in, redirecting home");
            response.sendRedirect("/?already-logged-in");
            return Result.SKIP_NO_CHAIN;
        }

        Logger.info(this.getClass().getName(), "Already logged in, redirecting to /dotAdmin");
        response.sendRedirect("/dotAdmin");
        return Result.SKIP_NO_CHAIN;
    }

}
