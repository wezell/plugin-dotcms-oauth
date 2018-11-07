package com.dotcms.osgi.oauth.util;

import static com.dotcms.osgi.oauth.util.OAuthPropertyBundle.getProperty;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.dotcms.enterprise.PasswordFactoryProxy;
import com.dotcms.enterprise.de.qaware.heimdall.PasswordException;
import com.dotcms.osgi.oauth.service.DotService;
import com.dotcms.rendering.velocity.viewtools.JSONTool;
import com.dotmarketing.business.APILocator;
import com.dotmarketing.business.Role;
import com.dotmarketing.cms.factories.PublicEncryptionFactory;
import com.dotmarketing.exception.DotDataException;
import com.dotmarketing.exception.DotSecurityException;
import com.dotmarketing.util.Logger;
import com.dotmarketing.util.UUIDGenerator;
import com.dotmarketing.util.json.JSONException;
import com.dotmarketing.util.json.JSONObject;
import com.liferay.portal.auth.PrincipalThreadLocal;
import com.liferay.portal.model.User;
import com.liferay.portal.util.WebKeys;
import java.util.Collection;
import java.util.Date;
import java.util.StringTokenizer;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.scribe.builder.api.DefaultApi20;
import org.scribe.exceptions.OAuthException;
import org.scribe.model.OAuthConstants;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.oauth.OAuthService;
import org.scribe.utils.OAuthEncoder;
import org.scribe.utils.Preconditions;

/**
 * @author Jonathan Gamba 8/24/18
 */
public class OauthUtils {

    public static final String OAUTH_PROVIDER = "OAUTH_PROVIDER";
    public static final String OAUTH_PROVIDER_DEFAULT = "DEFAULT_OAUTH_PROVIDER";
    public static final String OAUTH_REDIRECT = "OAUTH_REDIRECT";
    public static final String OAUTH_SERVICE = "OAUTH_SERVICE";
    public static final String OAUTH_API_PROVIDER = "OAUTH_API_PROVIDER";

    public static final String ROLES_TO_ADD = "ROLES_TO_ADD";
    public static final String CALLBACK_URL = "CALLBACK_URL";

    public static final String NATIVE = "native";
    public static final String REFERRER = "referrer";

    public static final String JAVAX_SERVLET_FORWARD_REQUEST_URI = "javax.servlet.forward.request_uri";

    public static final String FEMALE = "female";
    public static final String GENDER = "gender";

    public static final String REMEMBER_ME = "rememberMe";

    public static final String EMPTY_SECRET = "";

    private static class SingletonHolder {

        private static final OauthUtils INSTANCE = new OauthUtils();
    }

    public static OauthUtils getInstance() {
        return OauthUtils.SingletonHolder.INSTANCE;
    }

    private OauthUtils() {
        // singleton
    }

    public boolean forFrontEnd() {

        final String useFor = OAuthPropertyBundle.getProperty("USE_OAUTH_FOR", "")
                .toLowerCase();
        return useFor.contains("frontend");
    }

    public boolean forBackEnd() {

        final String useFor = OAuthPropertyBundle.getProperty("USE_OAUTH_FOR", "")
                .toLowerCase();
        return useFor.contains("backend");
    }

    public DefaultApi20 getAPIProvider(final HttpServletRequest request,
            final HttpSession session) {
        //Look for the provider to use
        String oauthProvider = getOauthProvider(request, session);

        DefaultApi20 apiProvider = null;
        if (null != oauthProvider) {

            try {
                //Initializing the API provider
                apiProvider = (DefaultApi20) Class.forName(oauthProvider).newInstance();
            } catch (Exception e) {
                Logger.error(this.getClass(),
                        String.format("Unable to instantiate API provider [%s] [%s]",
                                oauthProvider, e.getMessage()), e);
            }
        }

        return apiProvider;
    }

    private synchronized String getOauthProvider(final HttpServletRequest request,
            final HttpSession session) {

        String oauthProvider = getProperty(OAUTH_PROVIDER_DEFAULT,
                "org.scribe.builder.api.FacebookApi");

        if (null != session && null != session.getAttribute(OAUTH_PROVIDER)) {
            oauthProvider = (String) session.getAttribute(OAUTH_PROVIDER);
        }

        if (null != request.getParameter(OAUTH_PROVIDER)) {
            oauthProvider = request.getParameter(OAUTH_PROVIDER);
        }

        if (null != request.getAttribute(OAUTH_PROVIDER)) {
            oauthProvider = (String) request.getAttribute(OAUTH_PROVIDER);
        }

        if (null != session) {
            session.setAttribute(OAUTH_PROVIDER, oauthProvider);
        }

        return oauthProvider;
    } // getOauthProvider.

    /**
     * Default method implementation to extract the access token from the request token json
     * response
     */
    public Token extractToken(String response) {

        Preconditions.checkEmptyString(response,
                "Response body is incorrect. Can't extract a token from an empty string");

        try {
            final JSONObject jsonResponse = (JSONObject) new JSONTool().generate(response);
            if (jsonResponse.has(OAuthConstants.ACCESS_TOKEN)) {
                String token = OAuthEncoder
                        .decode(jsonResponse.get(OAuthConstants.ACCESS_TOKEN).toString());
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

    /**
     * This method gets the user from the remote service and either creates them in dotCMS and/or
     * updates
     */
    public User authenticate(final HttpServletRequest request, final HttpServletResponse response,
            final Token accessToken, final OAuthService service,
            final String protectedResourceUrl, final String firstNameProp,
            final String lastNameProp)
            throws DotDataException {

        final User systemUser = APILocator.getUserAPI().getSystemUser();

        //Now that we have the token lets try a call to a restricted end point
        final OAuthRequest oauthRequest = new OAuthRequest(Verb.GET, protectedResourceUrl);
        service.signRequest(accessToken, oauthRequest);
        final Response protectedCallResponse = oauthRequest.send();
        if (!protectedCallResponse.isSuccessful()) {
            throw new OAuthException(
                    String.format("Unable to connect to end point [%s] [%s]",
                            protectedResourceUrl,
                            protectedCallResponse.getMessage()));
        }

        //Parse the response in order to get the user data
        final JSONObject userJsonResponse = (JSONObject) new JSONTool()
                .generate(protectedCallResponse.getBody());

        User user = null;

        //Verify if the user already exist
        try {
            Logger.info(this.getClass(), "Loading an user!");
            final String email = userJsonResponse.getString("email");
            user = APILocator.getUserAPI()
                    .loadByUserByEmail(email, systemUser, false);
            Logger.info(this.getClass(), "User loaded!");
        } catch (Exception e) {
            Logger.warn(this, "No matching user, creating");
        }

        //Create the user if does not exist
        if (null == user) {

            try {
                Logger.info(this.getClass(), "User not found, creating one!");
                user = this
                        .createUser(firstNameProp, lastNameProp, userJsonResponse, systemUser);

                //Set the roles to the user
                setRoles(service, userJsonResponse, user);

            } catch (Exception e) {
                Logger.warn(this, "Error creating user:" + e.getMessage(), e);
                throw new DotDataException(e.getMessage());
            }
        }

        if (user.isActive()) {

            //Authenticate to dotCMS
            Logger.info(this.getClass(), "Doing login!");
            HttpSession httpSession = request.getSession(true);

            if (this.forFrontEnd()) {
                httpSession.setAttribute(com.dotmarketing.util.WebKeys.CMS_USER, user);
            }

            if (this.forBackEnd()) {

                final boolean rememberMe = "true"
                        .equalsIgnoreCase(getProperty(REMEMBER_ME, "true"));
                APILocator.getLoginServiceAPI().doCookieLogin(PublicEncryptionFactory.encryptString
                        (user.getUserId()), request, response, rememberMe);

                Logger.info(this.getClass(), "Finish back end login!");
                PrincipalThreadLocal.setName(user.getUserId());
                httpSession.setAttribute(WebKeys.USER_ID, user.getUserId());
            }

            //Keep the token in session
            httpSession.setAttribute(OAuthConstants.ACCESS_TOKEN, accessToken.getToken());
        }

        return user;
    } //authenticate.

    private void setRoles(final OAuthService service,
            final JSONObject userJsonResponse,
            final User user)
            throws DotDataException {

        /*
        NOTE: We are not creating roles here, the role needs to exist in order to be
        associated to the user
         */

        //First lets handle the roles we need to add from the configuration file
        Logger.info(this.getClass(), "User is active, adding roles!");
        final String rolesToAdd = getProperty(ROLES_TO_ADD);
        final StringTokenizer st = new StringTokenizer(rolesToAdd, ",;");
        while (st.hasMoreElements()) {
            final String roleKey = st.nextToken().trim();
            this.addRole(user, roleKey);
        }

        //Now from the remote server
        Collection<String> remoteRoles;
        if (service instanceof DotService) {
            remoteRoles = ((DotService) service).getGroups(user, userJsonResponse);

            if (null != remoteRoles && !remoteRoles.isEmpty()) {
                for (final String roleKey : remoteRoles) {
                    this.addRole(user, roleKey);
                }
            }
        }

    }

    private void addRole(final User user, final String roleKey) throws DotDataException {

        final Role role = APILocator.getRoleAPI().loadRoleByKey(roleKey);
        if (role != null && !APILocator.getRoleAPI().doesUserHaveRole(user, role)) {
            APILocator.getRoleAPI().addRoleToUser(role, user);
        }
    } // addRole.

    private User createUser(final String firstNameProp,
            final String lastNameProp,
            final JSONObject json,
            final User sys)
            throws JSONException, DotDataException, DotSecurityException, PasswordException {

        final String userId = UUIDGenerator.generateUuid();
        final String email = new String(json.getString("email").getBytes(), UTF_8);
        final String lastName = new String(json.getString(lastNameProp).getBytes(), UTF_8);
        final String firstName = new String(json.getString(firstNameProp).getBytes(), UTF_8);

        final User user = APILocator.getUserAPI().createUser(userId, email);

        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setActive(true);

        user.setCreateDate(new Date());
        if (!json.isNull(GENDER)) {
            user.setFemale(FEMALE.equals(json.getString(GENDER)));
        }
        user.setPassword(
                PasswordFactoryProxy.generateHash(
                        UUIDGenerator.generateUuid()
                                + "/"
                                + UUIDGenerator.generateUuid()
                ));
        user.setPasswordEncrypted(true);
        APILocator.getUserAPI().save(user, sys, false);

        return user;
    } // createUser.

}