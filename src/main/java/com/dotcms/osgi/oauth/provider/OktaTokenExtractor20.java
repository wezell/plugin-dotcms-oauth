package com.dotcms.osgi.oauth.provider;

import com.dotcms.rendering.velocity.viewtools.JSONTool;
import com.dotmarketing.util.json.JSONObject;
import org.scribe.exceptions.OAuthException;
import org.scribe.extractors.AccessTokenExtractor;
import org.scribe.model.Token;
import org.scribe.utils.OAuthEncoder;
import org.scribe.utils.Preconditions;

/**
 * @author Jonathan Gamba 8/25/18
 */
public class OktaTokenExtractor20 implements AccessTokenExtractor {

    private final static String ACCESS_TOKEN = "access_token";
    private static final String EMPTY_SECRET = "";

    @Override
    public Token extract(String response) {

        Preconditions.checkEmptyString(response,
                "Response body is incorrect. Can't extract a token from an empty string");

        try {
            final JSONObject jsonResponse = (JSONObject) new JSONTool().generate(response);
            if (jsonResponse.has(ACCESS_TOKEN)) {
                String token = OAuthEncoder.decode(jsonResponse.get(ACCESS_TOKEN).toString());
                return new Token(token, EMPTY_SECRET, response);
            } else {
                throw new OAuthException(
                        "Response body is incorrect. Can't extract a token from this: '" + response
                                + "'", null);
            }
        } catch (Exception e) {
            throw new OAuthException(
                    "Response body is incorrect. Can't extract a token from this: '" + response
                            + "'", null);
        }
    }

}