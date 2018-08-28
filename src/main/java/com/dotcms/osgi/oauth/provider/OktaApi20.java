package com.dotcms.osgi.oauth.provider;

import static com.dotcms.osgi.oauth.util.OAuthPropertyBundle.getProperty;

import com.dotcms.rendering.velocity.viewtools.JSONTool;
import com.dotmarketing.util.json.JSONArray;
import com.dotmarketing.util.json.JSONException;
import com.dotmarketing.util.json.JSONObject;
import com.liferay.portal.model.User;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Random;
import org.scribe.builder.api.DefaultApi20;
import org.scribe.exceptions.OAuthException;
import org.scribe.extractors.AccessTokenExtractor;
import org.scribe.model.OAuthConfig;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.oauth.OAuth20ServiceImpl;
import org.scribe.oauth.OAuthService;
import org.scribe.utils.OAuthEncoder;
import org.scribe.utils.Preconditions;

/**
 * @author Jonathan Gamba 8/24/18
 */
public class OktaApi20 extends DefaultApi20 implements DotProvider {

    private final String state;
    private OAuthConfig config;

    public OktaApi20() {
        this.state = "state_" + new Random().nextInt(999_999);
    }

    /**
     * https://developer.okta.com/blog/2018/04/10/oauth-authorization-code-grant-type
     */
    @Override
    public String getAccessTokenEndpoint() {
        return getBaseAccessTokenEndpoint() + "?grant_type=authorization_code";
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
                getState()
        );
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
        return this.state;
    }

    private String getSimpleName() {
        return this.getClass().getSimpleName();
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
     * Custom implementation (extra call) in order to get roles/groups from the Okta server as the
     * request that returns the user data does not have the user groups.
     */
    @Override
    public Collection<String> getGroups(User user) {

        final String providerName = getSimpleName();
        final String groupPrefix = getProperty(providerName + "_GROUP_PREFIX");
        final String organizationURL = getProperty(providerName + "_ORGANIZATION_URL");
        final String apiToken = getProperty(providerName + "_API_TOKEN");
        final String groupsResourceUrl = String
                .format(getProperty(providerName + "_GROUPS_RESOURCE_URL"), user.getEmailAddress());

        final OAuthRequest oauthGroupsRequest = new OAuthRequest(Verb.GET,
                organizationURL + groupsResourceUrl);
        oauthGroupsRequest.addHeader("Authorization", "SSWS " + apiToken);
        oauthGroupsRequest.addHeader("Content-Type", "application/json");
        oauthGroupsRequest.addHeader("Accept", "application/json");

        final Response groupsCallResponse = oauthGroupsRequest.send();
        if (!groupsCallResponse.isSuccessful()) {
            throw new OAuthException(
                    String.format("Unable to connect to end point [%s] [%s]",
                            groupsResourceUrl,
                            groupsCallResponse.getMessage()));
        }

        Collection<String> groups = new ArrayList<>();
        try {
            //Parse the response in order to get the user data
            final JSONArray groupsJsonResponse = (JSONArray) new JSONTool()
                    .generate(groupsCallResponse.getBody());

            for (int i = 0; i < groupsJsonResponse.length(); i++) {
                JSONObject groupJSONData = groupsJsonResponse.getJSONObject(i);

                final JSONObject profile = groupJSONData.getJSONObject("profile");
                if (null != profile) {

                    final String group = profile.getString("name");
                    if (null != group) {

                        //Verify if we need to filter by prefix
                        if (null != groupPrefix && !groupPrefix.isEmpty()) {
                            if (group.startsWith(groupPrefix)) {
                                groups.add(group);
                            }
                        } else {
                            groups.add(group);
                        }
                    }
                }
            }
        } catch (JSONException e) {
            throw new OAuthException(
                    String.format("Unable to get groups in remote authentication server [%s] [%s]",
                            groupsResourceUrl,
                            groupsCallResponse.getMessage()), e);
        }

        return groups;
    }

    @Override
    public OAuthService createService(OAuthConfig config) {
        return new Okta20Service(this, config);
    }

    private class Okta20Service extends OAuth20ServiceImpl {

        Okta20Service(DefaultApi20 api, OAuthConfig config) {
            super(api, config);
        }

        @Override
        public void signRequest(Token accessToken, OAuthRequest request) {
            request.addHeader("Authorization", "Bearer " + accessToken.getToken());
        }
    }

}