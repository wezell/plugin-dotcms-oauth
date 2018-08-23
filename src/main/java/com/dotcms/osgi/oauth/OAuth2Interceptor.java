/*
 * WebSessionFilter
 *
 * A filter that recognizes return users who have chosen to have their login information remembered.
 * Creates a valid WebSession object and passes it a contact to use to fill its information
 *
 */
package com.dotcms.osgi.oauth;

import java.io.IOException;
import java.lang.reflect.Method;
import java.util.Date;
import java.util.Map;
import java.util.StringTokenizer;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.scribe.builder.ServiceBuilder;
import org.scribe.builder.api.DefaultApi20;
import org.scribe.builder.api.LinkedInApi;
import org.scribe.oauth.OAuth20ServiceImpl;

import com.dotcms.filters.interceptor.Result;
import com.dotcms.filters.interceptor.WebInterceptor;
import com.dotcms.osgi.oauth.util.OAuthPropertyBundle;
import com.dotcms.util.ReflectionUtils;

import com.dotmarketing.business.APILocator;
import com.dotmarketing.business.Role;

import com.dotmarketing.exception.DotDataException;
import com.dotmarketing.util.Logger;
import com.dotmarketing.util.UUIDGenerator;
import com.dotmarketing.util.json.JSONObject;

import com.google.common.collect.ImmutableMap;
import com.liferay.portal.auth.PrincipalThreadLocal;
import com.liferay.portal.model.User;
import com.liferay.portal.util.WebKeys;

public class OAuth2Interceptor implements WebInterceptor {

  private static final long serialVersionUID = -7036009330382977246L;

  public final static String OAUTH_PROVIDER = "OAUTH_PROVIDER";
  public final static String DEFAULT_OAUTH_PROVIDER="DEFAULT_OAUTH_PROVIDER";
  
  final Map<String,DefaultApi20> PROVIDERS = ImmutableMap.<String, DefaultApi20>builder()

      .build();


      
      
  
  private static String CALLBACK_URL, ROLES_TO_ADD;
  String useFor = OAuthPropertyBundle.getProperty("USE_OAUTH_FOR", "").toLowerCase();
  boolean frontEnd = useFor.contains("frontend");
  boolean backEnd = useFor.contains("backend");

  @Override
  public Result intercept(HttpServletRequest request, HttpServletResponse response)  {


    HttpSession session = request.getSession(false);
    String path = request.getRequestURI();
    User user = null;
    Result result = Result.NEXT;

    final String CALLBACK_HOST =
        request.getScheme() + "://" + ((request.getServerPort() == 80 || request.getServerPort() == 443) ? request.getServerName()
            : request.getServerName() + ":" + request.getServerPort());

    final String providerStr = (request.getParameter(OAUTH_PROVIDER) != null) ? request.getParameter(OAUTH_PROVIDER)
        : (session.getAttribute(OAUTH_PROVIDER) != null) ? (String) session.getAttribute(OAUTH_PROVIDER)
            : OAuthPropertyBundle.getProperty(DEFAULT_OAUTH_PROVIDER);



    
        
    session.setAttribute("OAUTH_PROVIDER", providerStr);

    DefaultApi20 provider =  PROVIDERS.get(providerStr);
    
    OAuth20ServiceImpl service=null;

    service = new ServiceBuilder()
    .apiSecret(API_SECRET)
    .build(provider);

    Method method = clazz.getMethod("instance");
    DefaultApi20 api = (DefaultApi20) method.invoke(apiClass, new Object[] {});




    final OAuth20Service service = new ServiceBuilder(API_KEY).apiSecret(API_SECRET).scope(SCOPE).callback(CALLBACK_HOST).build(api);


    user = (com.liferay.portal.model.User) session.getAttribute(com.dotmarketing.util.WebKeys.CMS_USER);
    if (user == null) {
      try {
        user = com.liferay.portal.util.PortalUtil.getUser(request);
      } catch (Exception nsue) {
        Logger.warn(this, "Exception trying to getUser: " + nsue.getMessage(), nsue);
      }
    }


    // if the user is already logged in
    if (user != null) {
      Logger.error(this.getClass(), "Already logged in, redirecting home");
      response.reset();
      response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
      response.setHeader("Location", "/?already-logged-in");
      return;
    }


    if (path.contains(CALLBACK_URL)) {
      try {

        doCallback(request, response, service, PROTECTED_RESOURCE_URL, FIRST_NAME_PROP, LAST_NAME_PROP);

        // redirect onward!
        String authorizationUrl = (String) session.getAttribute("OAUTH_REDIRECT");
        if (authorizationUrl == null)
          authorizationUrl = "/?logged-in";
        request.getSession().removeAttribute("OAUTH_REDIRECT");
        response.reset();
        response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
        response.setHeader("Location", authorizationUrl);
      } catch (Exception e) {
        e.printStackTrace();
        throw new ServletException(e);

      }

    } else {
      // Send for authorization
      sendForAuthorization(request, response, service);


    }
    return result;
  }


  /**
   * This method gets the user from the remote service and either creates them in Dotcms and/or
   * updates
   * 
   * @param request
   * @param service
   * @return
   * @throws DotDataException
   */
  private User doCallback(HttpServletRequest request, HttpServletResponse response, OAuthService service, String callBackUrl,
      String firstNameProp, String lastNameProp) throws DotDataException {

    Verifier verifier = new Verifier(request.getParameter("code"));

    Token accessToken = service.getAccessToken(null, verifier);
    Logger.debug(this.getClass(), "Got the Access Token!");

    OAuthRequest quest = new OAuthRequest(Verb.GET, callBackUrl);
    service.signRequest(accessToken, quest);
    Response sponse = quest.send();

    JSONObject json = new JSONTool().generate(sponse.getBody());

    User sys = APILocator.getUserAPI().getSystemUser();
    User u = null;
    try {
      u = APILocator.getUserAPI().loadByUserByEmail(json.getString("email"), sys, false);

    } catch (Exception e) {
      Logger.warn(this, "No matching user, creating");
    }
    if (u == null) {
      try {

        String userId = UUIDGenerator.generateUuid();
        String email = new String(json.getString("email").getBytes(), "UTF-8");
        String lastName = new String(json.getString(lastNameProp).getBytes(), "UTF-8");
        String firstName = new String(json.getString(firstNameProp).getBytes(), "UTF-8");

        u = APILocator.getUserAPI().createUser(userId, email);

        u.setFirstName(firstName);
        u.setLastName(lastName);
        u.setActive(true);

        u.setCreateDate(new Date());
        u.setFemale("female".equals(json.getString("gender")));
        u.setPassword(PublicEncryptionFactory.digestString(UUIDGenerator.generateUuid() + "/" + UUIDGenerator.generateUuid()));
        u.setPasswordEncrypted(true);

        APILocator.getUserAPI().save(u, sys, false);

      } catch (Exception e) {
        Logger.warn(this, "Error creating user:" + e.getMessage(), e);
        throw new DotDataException(e.getMessage());
      }
    }

    if (!u.isActive()) {
      return u;
    }

    StringTokenizer st = new StringTokenizer(ROLES_TO_ADD, ",;");
    while (st.hasMoreElements()) {
      String roleKey = st.nextToken().trim();
      Role r = APILocator.getRoleAPI().loadRoleByKey(roleKey);
      if (r == null) {
        continue;

      }
      if (!APILocator.getRoleAPI().doesUserHaveRole(u, r)) {
        APILocator.getRoleAPI().addRoleToUser(r, u);
      }
    }
    LoginFactory.doCookieLogin(PublicEncryptionFactory.encryptString(u.getUserId()), request, response);
    if (backEnd) {
      PrincipalThreadLocal.setName(u.getUserId());
      request.getSession().setAttribute(WebKeys.USER_ID, u.getUserId());
    }

    return u;

  }

  private void sendForAuthorization(HttpServletRequest request, HttpServletResponse response, OAuthService service) {
    String retUrl = (String) request.getAttribute("javax.servlet.forward.request_uri");

    if (request.getSession().getAttribute("OAUTH_REDIRECT") != null) {
      retUrl = (String) request.getSession().getAttribute("OAUTH_REDIRECT");
    }
    if (request.getParameter("referrer") != null) {
      retUrl = request.getParameter("referrer");
    }
    request.getSession().setAttribute("OAUTH_REDIRECT", retUrl);

    String authorizationUrl = service.getAuthorizationUrl(null);
    response.reset();
    response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
    response.setHeader("Location", authorizationUrl);
    return;
  }



  @Override
  public void init(FilterConfig config) throws ServletException {
    ROLES_TO_ADD = OAuthPropertyBundle.getProperty("ROLES_TO_ADD");
    CALLBACK_URL = OAuthPropertyBundle.getProperty("CALLBACK_URL");

  }


  @Override
  public void destroy() {
    // TODO Auto-generated method stub
    
  }

}
