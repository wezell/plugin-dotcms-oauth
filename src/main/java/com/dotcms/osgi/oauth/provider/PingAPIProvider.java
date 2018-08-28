package com.dotcms.osgi.oauth.provider;

import static com.dotcms.osgi.oauth.util.OAuthPropertyBundle.getProperty;

import com.dotcms.osgi.oauth.service.DotService;
import com.dotcms.rendering.velocity.viewtools.JSONTool;
import com.dotmarketing.util.json.JSONException;
import com.dotmarketing.util.json.JSONObject;
import com.liferay.portal.model.User;
import java.util.Arrays;
import java.util.Collection;
import java.util.Random;
import org.scribe.builder.api.DefaultApi20;
import org.scribe.exceptions.OAuthException;
import org.scribe.extractors.AccessTokenExtractor;
import org.scribe.model.OAuthConfig;
import org.scribe.model.OAuthConstants;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuth20ServiceImpl;
import org.scribe.oauth.OAuthService;
import org.scribe.utils.OAuthEncoder;
import org.scribe.utils.Preconditions;

/**
 * https://www.pingidentity.com/content/developer/en/resources/oauth-2-0-developers-guide.html
 * https://www.pingidentity.com/content/developer/en/resources/openid-connect-developers-guide/basic-client-profile.html
 * https://docs.pingidentity.com/bundle/pf_sm_pingfederateOauth20Endpoints_pf83/page/concept/oAuth2_0Endpoints.html
 *
 * @author Jonathan Gamba 8/28/18
 */
public class PingAPIProvider extends DefaultApi20 implements DotProvider {

    private final String state;

    public PingAPIProvider() {
        this.state = "state_" + new Random().nextInt(999_999);
    }

    @Override
    public String getAccessTokenEndpoint() {
        return String.format("%s/as/token.oauth2", getOrganizationURL());
    }

    @Override
    public Verb getAccessTokenVerb() {
        return Verb.POST;
    }

    @Override
    public String getAuthorizationUrl(OAuthConfig config) {
        return getBaseAuthorizationUrl() + String.format(""
                        + "?client_id=%s"
                        + "&client_secret=%s"
                        + "&response_type=%s"
                        + "&scope=%s"
                        + "&redirect_uri=%s"
                        + "&state=%s",
                config.getApiKey(),
                config.getApiSecret(),
                getResponseType(),
                config.getScope(),
                config.getCallback(),
                getState()
        );
    }

    private String getBaseAuthorizationUrl() {
        return String.format("%s/as/authorization.oauth2", getOrganizationURL());
    }

    private String getOrganizationURL() {
        return getProperty(getSimpleName() + "_ORGANIZATION_URL");
    }

    /**
     * Simple command object that extracts a {@link Token} from a String
     */
    public AccessTokenExtractor getAccessTokenExtractor() {

        return new AccessTokenExtractor() {

            private final static String ACCESS_TOKEN = "access_token";
            private static final String EMPTY_SECRET = "";

            @Override
            public Token extract(String response) {

                Preconditions.checkEmptyString(response,
                        "Response body is incorrect. Can't extract a token from an empty string");

                try {
                    final JSONObject jsonResponse = (JSONObject) new JSONTool().generate(response);
                    if (jsonResponse.has(ACCESS_TOKEN)) {
                        String token = OAuthEncoder
                                .decode(jsonResponse.get(ACCESS_TOKEN).toString());
                        return new Token(token, EMPTY_SECRET, response);
                    } else {
                        throw new OAuthException(
                                "Response body is incorrect. Can't extract a token from this: '"
                                        + response
                                        + "'", null);
                    }
                } catch (Exception e) {
                    throw new OAuthException(
                            "Response body is incorrect. Can't extract a token from this: '"
                                    + response
                                    + "'", null);
                }
            }
        };
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
        return this.state;
    }

    private String getSimpleName() {
        return this.getClass().getSimpleName();
    }

    @Override
    public OAuthService createService(OAuthConfig config) {
        return new PingService(this, config);
    }

    private class PingService extends OAuth20ServiceImpl implements DotService {

        DefaultApi20 api;
        OAuthConfig config;

        PingService(DefaultApi20 api, OAuthConfig config) {
            super(api, config);
            this.api = api;
            this.config = config;
        }

        @Override
        public void signRequest(Token accessToken, OAuthRequest request) {
            request.addQuerystringParameter(OAuthConstants.ACCESS_TOKEN, accessToken.getToken());
        }

        @Override
        public Token getAccessToken(Token requestToken, Verifier verifier) {

            OAuthRequest request = new OAuthRequest(api.getAccessTokenVerb(),
                    api.getAccessTokenEndpoint());

            request.addQuerystringParameter(OAuthConstants.CODE, verifier.getValue());
            request.addQuerystringParameter("grant_type", "authorization_code");
            request.addQuerystringParameter(OAuthConstants.REDIRECT_URI, config.getCallback());
            if (config.hasScope()) {
                request.addQuerystringParameter(OAuthConstants.SCOPE, config.getScope());
            }

            request.addHeader("Content-Type", "application/x-www-form-urlencoded");

            request.addBodyParameter("client_id", config.getApiKey());
            request.addBodyParameter("client_secret", config.getApiSecret());

            Response response = request.send();
            return api.getAccessTokenExtractor().extract(response.getBody());
        }

        @Override
        public Collection<String> getGroups(User user, final JSONObject userJsonResponse) {

            Collection<String> groupsCollection = null;
            try {
                if (null != userJsonResponse && userJsonResponse.has("groups")) {

                    final String groups = userJsonResponse.getString("groups");
                    String[] groupsArray = groups.split(",");
                    groupsCollection = Arrays.asList(groupsArray);
                }
            } catch (JSONException e) {
                throw new OAuthException(
                        String.format(
                                "Unable to get groups from the remote user data [%s]",
                                e.getMessage()), e);
            }
            return groupsCollection;
        }

    }

}