package com.dotcms.osgi.oauth.provider;

import com.dotcms.osgi.oauth.util.OauthUtils;
import org.scribe.builder.api.FacebookApi;
import org.scribe.extractors.AccessTokenExtractor;
import org.scribe.model.Token;

/**
 * @author Jonathan Gamba 9/7/18
 */
public class Facebook20Api extends FacebookApi {

    @Override
    public AccessTokenExtractor getAccessTokenExtractor() {

        return new AccessTokenExtractor() {

            @Override
            public Token extract(String response) {
                return OauthUtils.getInstance().extractToken(response);
            }

        };
    }

}