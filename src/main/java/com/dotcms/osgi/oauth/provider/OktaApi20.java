package com.dotcms.osgi.oauth.provider;

import static com.dotcms.osgi.oauth.util.OAuthPropertyBundle.getProperty;

import java.util.Random;
import org.scribe.builder.api.DefaultApi20;
import org.scribe.extractors.AccessTokenExtractor;
import org.scribe.model.OAuthConfig;
import org.scribe.model.Verb;

/**
 * @author Jonathan Gamba 8/24/18
 */
public class OktaApi20 extends DefaultApi20 {

    private OAuthConfig config;

    public AccessTokenExtractor getAccessTokenExtractor() {
        return new OktaTokenExtractor20();
    }

    /**
     * https://developer.okta.com/blog/2018/04/10/oauth-authorization-code-grant-type
     */
    @Override
    public String getAccessTokenEndpoint() {
        return getBaseAccessTokenEndpoint() + String.format(""
                        + "?grant_type=authorization_code"
                        + "&redirect_uri=%s",
                this.config.getCallback()
        );
    }

    private String getBaseAccessTokenEndpoint() {
        return String.format("%s/oauth2/v1/token", getOrganizationURL());
    }

    @Override
    public Verb getAccessTokenVerb() {
        return Verb.POST;
    }

    /**
     * This is a starting point for browser-based OpenID Connect flows such as the implicit and
     * authorization code flows. This request authenticates the user and returns tokens along with
     * an authorization grant to the client application as a part of the callback response.
     * https://developer.okta.com/authentication-guide/implementing-authentication/auth-code
     */
    @Override
    public String getAuthorizationUrl(OAuthConfig config) {

        this.config = config;

        /*
        NOTE: The callback domain must be added as a trusted origin -> admin/access/api/trusted_origins
        also can be configured in Applications -> Your application -> General
         */

        return getBaseAuthorizationUrl() + String.format(""
                        + "?client_id=%s"
                        + "&response_type=%s"
                        + "&scope=%s"
                        + "&redirect_uri=%s"
                        + "&state=%s",
                config.getApiKey(),
                getResponseType(),
                config.getScope(),
                config.getCallback(),
                getState());
    }

    private String getBaseAuthorizationUrl() {
        return String.format("%s/oauth2/v1/authorize", getOrganizationURL());
    }

    private String getOrganizationURL() {
        return getProperty(getSimpleName() + "_ORGANIZATION_URL");
    }

    /**
     * response_type is code, indicating that we are using the authorization code grant type.
     */
    private String getResponseType() {
        return "code";
    }

    /**
     * state is an arbitrary alphanumeric string that the authorization server will reproduce when
     * redirecting the user-agent back to the client. This is used to help prevent cross-site
     * request forgery.
     */
    private String getState() {
        return "state_" + new Random().nextInt(999_999);
    }

    private String getSimpleName() {
        return this.getClass().getSimpleName();
    }

}