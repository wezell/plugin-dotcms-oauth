/*
 * WebSessionFilter
 *
 * A filter that recognizes return users who have chosen to have their login information remembered.
 * Creates a valid WebSession object and passes it a contact to use to fill its information
 *
 */
package com.dotcms.osgi.oauth.interceptor;

import static com.dotcms.osgi.oauth.OauthUtils.CALLBACK_URL;
import static com.dotcms.osgi.oauth.OauthUtils.CODE_PARAM_KEY;
import static com.dotcms.osgi.oauth.OauthUtils.FEMALE;
import static com.dotcms.osgi.oauth.OauthUtils.GENDER;
import static com.dotcms.osgi.oauth.OauthUtils.OAUTH_API_PROVIDER;
import static com.dotcms.osgi.oauth.OauthUtils.OAUTH_REDIRECT;
import static com.dotcms.osgi.oauth.OauthUtils.OAUTH_SERVICE;
import static com.dotcms.osgi.oauth.OauthUtils.REMEMBER_ME;
import static com.dotcms.osgi.oauth.OauthUtils.ROLES_TO_ADD;
import static com.dotcms.osgi.oauth.OauthUtils.forBackEnd;
import static com.dotcms.osgi.oauth.OauthUtils.forFrontEnd;
import static com.dotcms.osgi.oauth.util.OAuthPropertyBundle.getProperty;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.dotcms.enterprise.PasswordFactoryProxy;
import com.dotcms.enterprise.de.qaware.heimdall.PasswordException;
import com.dotcms.filters.interceptor.Result;
import com.dotcms.filters.interceptor.WebInterceptor;
import com.dotcms.osgi.oauth.provider.OktaApi20;
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
import java.io.IOException;
import java.util.Date;
import java.util.StringTokenizer;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.scribe.builder.api.DefaultApi20;
import org.scribe.exceptions.OAuthException;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuthService;

public class AutoLoginOAuthInterceptor implements WebInterceptor {

    private static final String NAME = "AutoLoginOAuthInterceptor_5_0_1";
    private final String oauthCallBackURL;
    private final boolean isFrontEnd;
    private final boolean isBackEnd;
    private final User systemUser;

    public AutoLoginOAuthInterceptor() throws DotDataException {
        this.oauthCallBackURL = getProperty(CALLBACK_URL);
        this.isFrontEnd = forFrontEnd();
        this.isBackEnd = forBackEnd();
        this.systemUser = APILocator.getUserAPI().getSystemUser();
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public Result intercept(HttpServletRequest request, HttpServletResponse response) {
        Result result = Result.NEXT;

        //If we already have an user we can continue
        boolean isLoggedInUser = APILocator.getLoginServiceAPI().isLoggedIn(request);
        if (!isLoggedInUser) {

            final HttpSession session = request.getSession(false);

            boolean requestingAuthentication = false;
            if (null != this.oauthCallBackURL) {
                requestingAuthentication = request.getRequestURI().startsWith(oauthCallBackURL);
            }

            if (requestingAuthentication) {

                final String responseCode = request.getParameter(CODE_PARAM_KEY);
                if (null != responseCode) {

                    Logger.info(this.getClass(), "Code param found, doing callback");
                    try {

                        final OAuthService oAuthService = (OAuthService) session
                                .getAttribute(OAUTH_SERVICE);
                        final DefaultApi20 apiProvider = (DefaultApi20) session
                                .getAttribute(OAUTH_API_PROVIDER);

                        final String providerName = apiProvider.getClass().getSimpleName();
                        final String protectedResourceUrl = getProperty(
                                providerName + "_PROTECTED_RESOURCE_URL");
                        final String firstNameProp = getProperty(providerName + "_FIRST_NAME_PROP");
                        final String lastNameProp = getProperty(providerName + "_LAST_NAME_PROP");

                        //With the authentication code lets try to authenticate to dotCMS
                        this.authenticate(request, response, apiProvider, oAuthService,
                                protectedResourceUrl, firstNameProp, lastNameProp);

                        // redirect onward!
                        final String authorizationUrl = (String) session
                                .getAttribute(OAUTH_REDIRECT);

                        if (authorizationUrl == null) {
                            this.alreadyLoggedIn(response);
                        } else {
                            session.removeAttribute(OAUTH_REDIRECT);
                            session.removeAttribute(OAUTH_SERVICE);
                            session.removeAttribute(OAUTH_API_PROVIDER);
                            response.sendRedirect(authorizationUrl);
                            result = Result.SKIP_NO_CHAIN; // needs to stop the filter chain.
                        }
                    } catch (Exception e) {
                        Logger.error(this, e.getMessage(), e);
                    }

                }
            }
        }

        return result;
    }

    /**
     * This method gets the user from the remote service and either creates them in dotCMS and/or
     * updates
     *
     * @return User
     */
    private User authenticate(final HttpServletRequest request, final HttpServletResponse response,
            final DefaultApi20 defaultApi20,
            final OAuthService service, final String protectedResourceUrl,
            final String firstNameProp, final String lastNameProp) throws DotDataException {

        //Request the access token with the authentication code
        final Verifier verifier = new Verifier(request.getParameter("code"));
        final Token accessToken = service.getAccessToken(null, verifier);
        Logger.info(this.getClass(), "Got the Access Token!");

        //Now that we have the token lets try a call to a restricted end point
        final OAuthRequest oauthRequest = new OAuthRequest(Verb.GET, protectedResourceUrl);

        if (defaultApi20 instanceof OktaApi20) {
            oauthRequest.addHeader("Authorization", "Bearer " + accessToken.getToken());
        } else {
            service.signRequest(accessToken, oauthRequest);
        }

        final Response protectedCallResponse = oauthRequest.send();
        if (!protectedCallResponse.isSuccessful()) {
            throw new OAuthException(
                    String.format("Unable to connect to end point [%s] [%s]",
                            protectedResourceUrl,
                            protectedCallResponse.getMessage()));
        }

        //Parse the response in order to get the user data
        final JSONObject jsonResponse = (JSONObject) new JSONTool()
                .generate(protectedCallResponse.getBody());

        User user = null;

        try {
            //Verify if the user already exist
            Logger.info(this.getClass(), "Loading an user!");
            user = APILocator.getUserAPI()
                    .loadByUserByEmail(jsonResponse.getString("email"), this.systemUser, false);
            Logger.info(this.getClass(), "User loaded!");
        } catch (Exception e) {
            Logger.warn(this, "No matching user, creating");
        }

        //Create the user if does not exist
        if (user == null) {
            try {
                Logger.info(this.getClass(), "User not found, creating one!");
                user = this.createUser(firstNameProp, lastNameProp, jsonResponse, this.systemUser);
            } catch (Exception e) {
                Logger.warn(this, "Error creating user:" + e.getMessage(), e);
                throw new DotDataException(e.getMessage());
            }
        }

        if (user.isActive()) {

            Logger.info(this.getClass(), "User is active, adding roles!");
            final String rolesToAdd = getProperty(ROLES_TO_ADD);
            final StringTokenizer st = new StringTokenizer(rolesToAdd, ",;");
            while (st.hasMoreElements()) {
                final String roleKey = st.nextToken().trim();
                this.addRole(user, roleKey);
            }

            Logger.info(this.getClass(), "Doing login!");
            final boolean rememberMe = "true".equalsIgnoreCase(getProperty(REMEMBER_ME, "true"));
            APILocator.getLoginServiceAPI().doCookieLogin(PublicEncryptionFactory.encryptString
                    (user.getUserId()), request, response, rememberMe);

            if (this.isBackEnd) {
                Logger.info(this.getClass(), "Finish back end login!");
                PrincipalThreadLocal.setName(user.getUserId());
                final HttpSession httpSession = request.getSession(true);
                httpSession.setAttribute(WebKeys.USER_ID, user.getUserId());
            }
        }

        return user;
    } //authenticate.

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

    private void alreadyLoggedIn(HttpServletResponse response) throws IOException {

        if (this.isBackEnd) {
            Logger.info(this.getClass(), "Already logged in, redirecting to /dotAdmin");
        } else {
            Logger.info(this.getClass(), "Already logged in, redirecting home");
        }

        response.sendRedirect((this.isBackEnd) ? "/dotAdmin" : "/?already-logged-in");
    }

}