package com.dotcms.osgi.oauth.service;

import com.dotmarketing.util.json.JSONObject;
import com.liferay.portal.model.User;
import java.util.Collection;

/**
 * @author Jonathan Gamba 8/28/18
 */
public interface DotService {

    /**
     * Custom implementation (extra call) in order to get roles/groups from the authentication
     * server if required, most of the implementations will return groups along with the user data,
     * use this in case an extra call is required.
     */
    Collection<String> getGroups(User user, final JSONObject userJsonResponse);

}