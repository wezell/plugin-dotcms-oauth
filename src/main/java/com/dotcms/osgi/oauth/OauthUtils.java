package com.dotcms.osgi.oauth;

import com.dotcms.osgi.oauth.util.OAuthPropertyBundle;

/**
 * @author Jonathan Gamba 8/24/18
 */
public class OauthUtils {

    public static final String OAUTH_URL = "/oauth2";
    public static final String OAUTH_PROVIDER = "OAUTH_PROVIDER";
    public static final String OAUTH_PROVIDER_DEFAULT = "DEFAULT_OAUTH_PROVIDER";
    public static final String OAUTH_REDIRECT = "OAUTH_REDIRECT";
    public static final String OAUTH_SERVICE = "OAUTH_SERVICE";
    public static final String OAUTH_API_PROVIDER = "OAUTH_API_PROVIDER";

    public static final String ROLES_TO_ADD = "ROLES_TO_ADD";
    public static final String CALLBACK_URL = "CALLBACK_URL";

    public static final String NATIVE = "native";
    public static final String REFERRER = "referrer";
    public static final String CODE_PARAM_KEY = "code";

    public static final String JAVAX_SERVLET_FORWARD_REQUEST_URI = "javax.servlet.forward.request_uri";

    public static final String FEMALE = "female";
    public static final String GENDER = "gender";

    public static final String REMEMBER_ME = "rememberMe";

    public static boolean forFrontEnd() {

        final String useFor = OAuthPropertyBundle.getProperty("USE_OAUTH_FOR", "")
                .toLowerCase();
        return useFor.contains("frontend");
    }

    public static boolean forBackEnd() {

        final String useFor = OAuthPropertyBundle.getProperty("USE_OAUTH_FOR", "")
                .toLowerCase();
        return useFor.contains("backend");
    }
}