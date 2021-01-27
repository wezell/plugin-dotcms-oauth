package com.dotcms.osgi.oauth.provider;


import java.util.HashMap;
import java.util.Map;
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
import com.dotmarketing.exception.DotRuntimeException;
import com.dotmarketing.util.UUIDGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.vavr.control.Try;

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

    private static final String MSFT_GRAPH_URL = "https://graph.microsoft.com/v1.0/me/messages";

    private static final String MSFT_ENDPOINT = "https://login.microsoftonline.com";
    private static final String MSFT_AUTHORIZATION = MSFT_ENDPOINT + "/common/oauth2/v2.0/authorize";
    private static final String MSFT_TOKEN = MSFT_ENDPOINT + "/common/oauth2/v2.0/token";

    private static final String MSFT_PROTECTED_RESOURCE="https://graph.microsoft.com/v1.0/me";
    
    private static final String MSFT_GROUP_RESOURCE="https://graph.microsoft.com/v1.0/me/memberOf";
    
    private final String state = UUIDGenerator.generateUuid();

    private static class InstanceHolder {

        private static final MicrosoftAzureActiveDirectoryApi INSTANCE = new MicrosoftAzureActiveDirectoryApi();
    }

    public static MicrosoftAzureActiveDirectoryApi instance() {
        return InstanceHolder.INSTANCE;
    }

    @Override
    public String getAccessTokenEndpoint() {

        return MSFT_TOKEN;
    }

    @Override
    public AccessTokenExtractor getAccessTokenExtractor() {
        return new AccessTokenExtractor() {

            public Token extract(String response) {
                Preconditions.checkEmptyString(response,
                                "Response body is incorrect. Can't extract a token from an empty string");


                HashMap<String,String> map = Try.of(()->new ObjectMapper().readValue(response, HashMap.class)).getOrElseThrow(e->new DotRuntimeException("bad response: "+response, e));
                if(map.containsKey("error")){
                    throw new  OAuthException("bad response: "+response);
                }

                
                return new Token(map.get("access_token"), "", response);
                

            }
        };

    }

    
    

    @Override
    public String getAuthorizationUrl(OAuthConfig config) {


        return String.format(MSFT_AUTHORIZATION

                        + "?client_id=%s" 
                        + "&response_type=%s" 
                        + "&scope=%s" 
                        + "&redirect_uri=%s" 
                        + "&state=%s",
                        OAuthEncoder.encode(config.getApiKey()), 
                        OAuthEncoder.encode(getResponseType()),
                        config.getScope(), 
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
            request.addBodyParameter(OAuthConstants.CLIENT_ID, config.getApiKey());
            request.addBodyParameter(OAuthConstants.CLIENT_SECRET, config.getApiSecret());
            request.addBodyParameter(OAuthConstants.CODE, verifier.getValue());
            request.addBodyParameter(OAuthConstants.REDIRECT_URI, config.getCallback());
            request.addBodyParameter("grant_type", "authorization_code");
            


            Response response = request.send();
            return api.getAccessTokenExtractor().extract(response.getBody());
        }


        @Override
        public void signRequest(Token accessToken, OAuthRequest request) {
            request.addHeader("Authorization", "Bearer " + accessToken.getToken());
            request.addHeader("Accept", "*/*");
        }

    }
}
