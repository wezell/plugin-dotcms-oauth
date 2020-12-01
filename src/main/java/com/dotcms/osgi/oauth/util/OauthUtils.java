package com.dotcms.osgi.oauth.util;

import static com.dotcms.osgi.oauth.util.OAuthPropertyBundle.getProperty;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import org.scribe.builder.api.DefaultApi20;
import org.scribe.exceptions.OAuthException;
import org.scribe.model.OAuthConstants;
import org.scribe.model.Token;
import org.scribe.utils.OAuthEncoder;
import org.scribe.utils.Preconditions;
import com.dotmarketing.util.Logger;

/**
 * @author Jonathan Gamba 8/24/18
 */
public class OauthUtils {

    public static final String OAUTH_PROVIDER = "OAUTH_PROVIDER";
    public static final String OAUTH_PROVIDER_DEFAULT = "DEFAULT_OAUTH_PROVIDER";
    public static final String OAUTH_REDIRECT = "OAUTH_REDIRECT";
    public static final String OAUTH_SERVICE = "OAUTH_SERVICE";
    public static final String OAUTH_API_PROVIDER = "OAUTH_API_PROVIDER";

    public static final String ROLES_TO_ADD = "ROLES_TO_ADD";
    public static final String CALLBACK_URL = "CALLBACK_URL";

    public static final String NATIVE = "native";
    public static final String REFERRER = "referrer";

    public static final String JAVAX_SERVLET_FORWARD_REQUEST_URI = "javax.servlet.forward.request_uri";

    public static final String FEMALE = "female";
    public static final String GENDER = "gender";

    public static final String REMEMBER_ME = "rememberMe";

    private static final String EMPTY_SECRET = "";

    private static class SingletonHolder {

        private static final OauthUtils INSTANCE = new OauthUtils();
    }

    public static OauthUtils getInstance() {
        return OauthUtils.SingletonHolder.INSTANCE;
    }

    private OauthUtils() {
        // singleton
    }

    public boolean forFrontEnd() {

        final String useFor = OAuthPropertyBundle.getProperty("USE_OAUTH_FOR", "").toLowerCase();
        return useFor.contains("frontend");
    }

    public boolean forBackEnd() {

        final String useFor = OAuthPropertyBundle.getProperty("USE_OAUTH_FOR", "").toLowerCase();
        return useFor.contains("backend");
    }

    public DefaultApi20 getAPIProvider(final HttpServletRequest request, final HttpSession session) {
        // Look for the provider to use
        String oauthProvider = getOauthProvider(request, session);

        DefaultApi20 apiProvider = null;
        if (null != oauthProvider) {

            try {
                // Initializing the API provider
                apiProvider = (DefaultApi20) Class.forName(oauthProvider).newInstance();
            } catch (Exception e) {
                Logger.error(this.getClass(), String.format("Unable to instantiate API provider [%s] [%s]",
                                oauthProvider, e.getMessage()), e);
            }
        }

        return apiProvider;
    }

    private synchronized String getOauthProvider(final HttpServletRequest request, final HttpSession session) {

        String oauthProvider = getProperty(OAUTH_PROVIDER_DEFAULT, "org.scribe.builder.api.FacebookApi");

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

    /**
     * Default method implementation to extract the access token from the request token json response
     */
    public Token extractToken(final String response) {

        Preconditions.checkEmptyString(response,
                        "Response body is incorrect. Can't extract a token from an empty string");

        try {

            Map<String, Object> json = (Map<String, Object>) new JsonUtil().generate(response);

            if (json.containsKey(OAuthConstants.ACCESS_TOKEN)) {
                String token = OAuthEncoder.decode(json.get(OAuthConstants.ACCESS_TOKEN).toString());
                return new Token(token, EMPTY_SECRET, response);
            } else {
                throw new OAuthException(
                                "Response body is incorrect. Can't extract a token from this: '" + response + "'",
                                null);
            }
        } catch (Exception e) {
            throw new OAuthException("Response body is incorrect. Can't extract a token from this: '" + response + "'",
                            null);
        }
    }

}
