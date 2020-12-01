package com.dotcms.osgi.oauth.service;

import java.util.Collection;
import java.util.Map;
import com.liferay.portal.model.User;

/**
 * @author Jonathan Gamba 8/28/18
 */
public interface DotService {

    /**
     * Custom implementation (extra call) in order to get roles/groups from the authentication
     * server if required, most of the implementations will return groups along with the user data,
     * use this in case an extra call is required.
     */
    Collection<String> getGroups(User user, final Map<String,Object> userJsonResponse);

    default void revokeToken(final String token) {}

}