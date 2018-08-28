package com.dotcms.osgi.oauth.interceptor;

import static com.dotcms.osgi.oauth.OauthUtils.CALLBACK_URL;
import static com.dotcms.osgi.oauth.OauthUtils.JAVAX_SERVLET_FORWARD_REQUEST_URI;
import static com.dotcms.osgi.oauth.OauthUtils.NATIVE;
import static com.dotcms.osgi.oauth.OauthUtils.OAUTH_API_PROVIDER;
import static com.dotcms.osgi.oauth.OauthUtils.OAUTH_PROVIDER;
import static com.dotcms.osgi.oauth.OauthUtils.OAUTH_PROVIDER_DEFAULT;
import static com.dotcms.osgi.oauth.OauthUtils.OAUTH_REDIRECT;
import static com.dotcms.osgi.oauth.OauthUtils.OAUTH_SERVICE;
import static com.dotcms.osgi.oauth.OauthUtils.REFERRER;
import static com.dotcms.osgi.oauth.OauthUtils.forBackEnd;
import static com.dotcms.osgi.oauth.OauthUtils.forFrontEnd;
import static com.dotcms.osgi.oauth.util.OAuthPropertyBundle.getProperty;

import com.dotcms.filters.interceptor.Result;
import com.dotcms.filters.interceptor.WebInterceptor;
import com.dotmarketing.business.APILocator;
import com.dotmarketing.util.Logger;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.scribe.builder.ServiceBuilder;
import org.scribe.builder.api.DefaultApi20;
import org.scribe.model.Token;
import org.scribe.oauth.OAuthService;

/**
 * This interceptor is used for handle the OAuth login check on DotCMS BE.
 *
 * @author jsanca
 */
public class LoginRequiredOAuthInterceptor implements WebInterceptor {

    private static final String NAME = "LoginRequiredOAuthInterceptor_5_0_1";

    private static final Token EMPTY_TOKEN = null;

    private final String oauthCallBackURL;
    private final boolean isFrontEnd;
    private final boolean isBackEnd;

    public LoginRequiredOAuthInterceptor() {
        this.oauthCallBackURL = getProperty(CALLBACK_URL);
        this.isFrontEnd = forFrontEnd();
        this.isBackEnd = forBackEnd();
    }

    @Override
    public String getName() {
        return NAME;
    }

    /**
     * This login required will be used for the BE, when the user is on BE, is not logged in and the
     * by pass native=true is not in the query string will redirect to the OAUTH Servlet in order to
     * do the authentication with OAUTH
     */
    @Override
    public Result intercept(final HttpServletRequest request, final HttpServletResponse response)
            throws IOException {

        Result result = Result.NEXT;

        //If we already have an user we can continue
        boolean isLoggedInUser = APILocator.getLoginServiceAPI().isLoggedIn(request);
        if (!isLoggedInUser) {

            final HttpSession session = request.getSession(false);

            String urlToVerify = null;
            if (this.isFrontEnd) {
                urlToVerify = "/dotCMS/login";
            } else if (this.isBackEnd) {
                urlToVerify = "/dotAdmin";
            }

            boolean requestingAuthentication = false;
            if (null != urlToVerify) {
                requestingAuthentication = request.getRequestURI().startsWith(urlToVerify);
            }

            if (requestingAuthentication && !Boolean.TRUE.toString()
                    .equalsIgnoreCase(request.getParameter(NATIVE))) {

                //Look for the provider to use
                DefaultApi20 apiProvider = getAPIProvider(request, session);
                if (null != apiProvider) {

                    final String callbackHost = this.getCallbackHost(request);
                    final String providerName = apiProvider.getClass().getSimpleName();
                    final String apiKey = getProperty(providerName + "_API_KEY");
                    final String apiSecret = getProperty(providerName + "_API_SECRET");
                    final String scope = getProperty(providerName + "_SCOPE");

                    // todo: this should be a factory based on the provider type
                    final OAuthService service = new ServiceBuilder()
                            .apiKey(apiKey)
                            .apiSecret(apiSecret)
                            .callback(callbackHost + this.oauthCallBackURL)
                            .provider(apiProvider)
                            .scope(scope)
                            .build();

                    // Send for authorization
                    Logger.info(this.getClass(), "Sending for authorization");
                    sendForAuthorization(request, response, service, apiProvider);
                    result = Result.SKIP_NO_CHAIN; // needs to stop the filter chain.
                }

            }
        }

        return result; // if it is log in, continue!
    } // intercept.

    private DefaultApi20 getAPIProvider(HttpServletRequest request, HttpSession session) {
        //Look for the provider to use
        String oauthProvider = getOauthProvider(request, session);

        DefaultApi20 apiProvider = null;
        if (null != oauthProvider) {

            try {
                //Initializing the API provider
                apiProvider = (DefaultApi20) Class.forName(oauthProvider).newInstance();
            } catch (Exception e) {
                Logger.error(this.getClass(),
                        String.format("Unable to instantiate API provider [%s] [%s]",
                                oauthProvider, e.getMessage()), e);
            }
        }

        return apiProvider;
    }

    private synchronized String getOauthProvider(final HttpServletRequest request, final HttpSession session) {

        String oauthProvider = getProperty(OAUTH_PROVIDER_DEFAULT,
                "org.scribe.builder.api.FacebookApi");

        if (null != session && null != session.getAttribute(OAUTH_PROVIDER)) {
            oauthProvider = (String) session.getAttribute(OAUTH_PROVIDER);
        }

        if (null != request.getParameter(OAUTH_PROVIDER)) {
            oauthProvider = request.getParameter(OAUTH_PROVIDER);
        }

        if (null != session) {
            session.setAttribute(OAUTH_PROVIDER, oauthProvider);
        }

        return oauthProvider;
    } // getOauthProvider.

    private void sendForAuthorization(final HttpServletRequest request,
            final HttpServletResponse response,
            final OAuthService service,
            final DefaultApi20 apiProvider) throws IOException {

        String retUrl = (String) request.getAttribute(JAVAX_SERVLET_FORWARD_REQUEST_URI);

        if (request.getSession().getAttribute(OAUTH_REDIRECT) != null) {
            retUrl = (String) request.getSession().getAttribute(OAUTH_REDIRECT);
        }

        if (request.getParameter(REFERRER) != null) {
            retUrl = request.getParameter(REFERRER);
        }

        request.getSession().setAttribute(OAUTH_REDIRECT, retUrl);
        request.getSession().setAttribute(OAUTH_SERVICE, service);
        request.getSession().setAttribute(OAUTH_API_PROVIDER, apiProvider);

        final String authorizationUrl = service.getAuthorizationUrl(EMPTY_TOKEN);
        Logger.info(this.getClass(), "Redirecting for authentication to: " + authorizationUrl);
        response.sendRedirect(authorizationUrl);
    }

    private String getCallbackHost(final HttpServletRequest request) {

        return request.getScheme() + "://" + (
                (request.getServerPort() == 80 || request.getServerPort() == 443) ?
                        request.getServerName()
                        : request.getServerName() + ":" + request.getServerPort());
    }

} // BackEndLoginRequiredOAuthInterceptor.