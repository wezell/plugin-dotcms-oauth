package com.dotcms.osgi.oauth.provider;


import java.util.regex.Matcher;
import java.util.regex.Pattern;
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
import org.scribe.utils.OAuthEncoder;
import org.scribe.utils.Preconditions;
import com.dotmarketing.util.UUIDGenerator;

/**
 * Microsoft Azure Active Directory Api
 *
 * @see <a href=
 *      "https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-protocols-oauth-code">
 *      Understand the OAuth 2.0 authorization code flow in Azure AD | Microsoft Docs</a>
 * @see <a href=
 *      "https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-devquickstarts-webapp-java">
 *      Azure AD Java web app Getting Started | Microsoft Docs</a>
 * @see <a href=
 *      "https://msdn.microsoft.com/en-us/library/azure/ad/graph/api/signed-in-user-operations">
 *      Azure AD Graph API Operations on the Signed-in User</a>
 * @see <a href="https://portal.azure.com">https://portal.azure.com</a>
 */
public class MicrosoftAzureActiveDirectoryApi extends DefaultApi20 implements DotProvider {

    private static final String MSFT_GRAPH_URL = "https://graph.microsoft.com";

    private static final String MSFT_LOGIN_URL = "https://login.microsoftonline.com";
    private static final String SLASH = "/";
    private static final String COMMON = "common";
    private static final String TOKEN_URI = "oauth2/token";
    private static final String AUTH_URI = "oauth2/authorize?resource=" + MSFT_GRAPH_URL;
    private static final String DEFAULT_SCOPE="openid User.Read profile email https://graph.microsoft.com/v1.0/me/memberOf";
    
    private final String state = new UUIDGenerator().generateUuid();

    private static class InstanceHolder {

        private static final MicrosoftAzureActiveDirectoryApi INSTANCE = new MicrosoftAzureActiveDirectoryApi();
    }

    public static MicrosoftAzureActiveDirectoryApi instance() {
        return InstanceHolder.INSTANCE;
    }

    @Override
    public String getAccessTokenEndpoint() {
        return MSFT_LOGIN_URL + SLASH + COMMON + SLASH + TOKEN_URI;
    }

    @Override
    public AccessTokenExtractor getAccessTokenExtractor() {
        return new AccessTokenExtractor() {

            public Token extract(String response) {
                Preconditions.checkEmptyString(response,
                                "Response body is incorrect. Can't extract a token from an empty string");

                String regex = "\"access_token\"\\s*:\\s*\"([^&\"]+)\"";
                Matcher matcher = Pattern.compile(regex).matcher(response);
                if (matcher.find()) {
                    String token = OAuthEncoder.decode(matcher.group(1));
                    return new Token(token, "", response);
                } else {
                    throw new OAuthException(
                                    "Response body is incorrect. Can't extract a token from this: '" + response + "'",
                                    null);
                }
            }
        };

    }


    @Override
    public String getAuthorizationUrl(OAuthConfig config) {


        return String.format(MSFT_LOGIN_URL + SLASH + COMMON + SLASH + AUTH_URI

                        + "&client_id=%s" 
                        + "&response_type=%s" 
                        + "&scope=%s" 
                        + "&redirect_uri=%s" 
                        + "&state=%s",
                        OAuthEncoder.encode(config.getApiKey()), 
                        OAuthEncoder.encode(getResponseType()),
                        OAuthEncoder.encode(config.getScope()), 
                        OAuthEncoder.encode(config.getCallback()), 
                        state);


    }

    private String getResponseType() {
        return "code";
    }

    @Override
    public Verb getAccessTokenVerb() {
        return Verb.POST;
    }


    @Override
    public MicrosoftAzureActiveDirectoryService createService(OAuthConfig config) {
        return new MicrosoftAzureActiveDirectoryService(this, config);
    }


    public class MicrosoftAzureActiveDirectoryService extends OAuth20ServiceImpl {
        private DefaultApi20 api;
        private OAuthConfig config;

        public MicrosoftAzureActiveDirectoryService(DefaultApi20 api, OAuthConfig config) {
            super(api, config);
            this.api = api;
            this.config = config;
        }


        @Override
        public Token getAccessToken(Token requestToken, Verifier verifier) {
            OAuthRequest request = new OAuthRequest(api.getAccessTokenVerb(), api.getAccessTokenEndpoint());


            request.addHeader("Content-Type", "application/x-www-form-urlencoded");

            request.addBodyParameter(OAuthConstants.CODE, verifier.getValue());
            request.addBodyParameter("grant_type", "authorization_code");
            request.addBodyParameter(OAuthConstants.REDIRECT_URI, config.getCallback());


            request.addBodyParameter(OAuthConstants.CLIENT_ID, config.getApiKey());
            request.addBodyParameter(OAuthConstants.CLIENT_SECRET, config.getApiSecret());

            Response response = request.send();
            return api.getAccessTokenExtractor().extract(response.getBody());
        }


        @Override
        public void signRequest(Token accessToken, OAuthRequest request) {
            request.addHeader("Authorization", "Bearer " + accessToken.getToken());
        }

    }
}
