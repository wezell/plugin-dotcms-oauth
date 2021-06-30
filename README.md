# OAuth 2 / Open Id Connect Auth

This is an osgi plugin that provides an example of single sign-on using OAuth2.  This intended to be a drop in replacement for the standard dotcms login, both for front end users and for backend users and effectively disables the out of the box authentication.  This plugin is provided as a code example and should not be used in a production environment without careful understanding of what the code does.

It provides examples for Google, Facebook, Okta and ping identity implementations. 

For reference:
* https://developers.google.com/accounts/docs/OAuth2
* https://developers.facebook.com/docs/facebook-login
* https://developer.okta.com/authentication-guide/
* https://www.pingidentity.com/content/developer/en/resources/oauth-2-0-developers-guide.html
 
### About the Implementaion
Under the covers, this plugin uses the very handy Scribe library to provide the the OAuth implementataions.  You can see the some of the providers that it supports.  These implementations should be supportable by this plugin but they will need some work.

https://github.com/scribejava/scribejava/tree/master/scribejava-apis/src/main/java/com/github/scribejava/apis

---

# Plugin Components

## Interceptors
### com.dotcms.osgi.oauth.interceptor.LoginRequiredOAuthInterceptor
Interceptor class that "intercepts" urls that require authentication, by default:
* For backend `/dotAdmin, /dwr, /c/`
* For front end `/dotCMS/login`

Those URLs can be changed directly in the interceptor class modifying the `getFilters` method.

https://github.com/dotCMS/plugin-dotcms-oauth/blob/master/src/main/java/com/dotcms/osgi/oauth/interceptor/LoginRequiredOAuthInterceptor.java#L61

When one of those URLs are intercepted the code based on the selected authentication provider will redirect the user in order to authenticate himself with the provider.

### com.dotcms.osgi.oauth.interceptor.OAuthCallbackInterceptor
Interceptor class that "intercepts" the configured call back url after the user is authenticated with the authentication provider.

You can change that url in the `oauth2.properties`:
* `CALLBACK_URL=/app/oauth2/callback`

When the call back url is intercepted the provider returns an authorization code that is use to request an authentication token in order to query the user data and authenticate him in dotCMS. 

### com.dotcms.osgi.oauth.interceptor.LogoutOAuthInterceptor
Interceptor class that "intercepts" logout urls, by default `/api/v1/logout, /dotCMS/logout`

Those URLs can be changed directly in the interceptor class modifying the `getFilters` method.

https://github.com/dotCMS/plugin-dotcms-oauth/blob/master/src/main/java/com/dotcms/osgi/oauth/interceptor/LogoutOAuthInterceptor.java#L40

In order to use this interceptor a revoke url must be configured in the Provider class (Not required).

## Providers

### com.dotcms.osgi.oauth.provider.Google20Api

Google oAuth2 provider. 

* Configuration
    ```
    Google20Api_API_KEY=YOUR_APPLICATION_KEY
    Google20Api_API_SECRET=YOUR_APPLICATION_SECRET_KEY
    Google20Api_SCOPE=https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile
    Google20Api_PROTECTED_RESOURCE_URL=https://www.googleapis.com/oauth2/v2/userinfo
    Google20Api_FIRST_NAME_PROP=given_name
    Google20Api_LAST_NAME_PROP=family_name
    ```
    
### com.dotcms.osgi.oauth.provider.Facebook20Api

Facebook oAuth2 provider.

* Configuration
    ```
    Facebook20Api_API_KEY=YOUR_APPLICATION_KEY
    Facebook20Api_API_SECRET=YOUR_APPLICATION_SECRET_KEY
    Facebook20Api_SCOPE=email user_about_me
    Facebook20Api_PROTECTED_RESOURCE_URL=https://graph.facebook.com/me?fields=name,first_name,last_name,email,id
    Facebook20Api_FIRST_NAME_PROP=first_name
    Facebook20Api_LAST_NAME_PROP=last_name
    ```

### com.dotcms.osgi.oauth.provider.Okta20Api

Okta oAuth2 provider.

* Configuration
    ```
    #https://developer.okta.com/authentication-guide/implementing-authentication/auth-code#1-setting-up-your-application
    #Client id
    Okta20Api_API_KEY=YOUR_CLIENT_ID
    #Client secret
    Okta20Api_API_SECRET=YOUR_CLIENT_SECRET
    
    #For groups
    #/admin/access/api/tokens -> Dashboard -> API -> Tokens
    Okta20Api_API_TOKEN=YOUR_API_TOKEN
    Okta20Api_GROUPS_RESOURCE_URL=/api/v1/users/%s/groups
    # https://developer.okta.com/docs/api/resources/oidc#scopes
    # Don't forget to add the groups scope to your server, Authorization servers -> Scopes
    Okta20Api_SCOPE=openid email profile groups
    Okta20Api_GROUP_PREFIX=cms_
    #For groups
    
    Okta20Api_ORGANIZATION_URL=YOUR_OKTA_ORG_URL
    Okta20Api_PROTECTED_RESOURCE_URL=YOUR_OKTA_ORG_URL/oauth2/v1/userinfo
    Okta20Api_FIRST_NAME_PROP=given_name
    Okta20Api_LAST_NAME_PROP=family_name
    ```

### com.dotcms.osgi.oauth.provider.Ping20Api

Ping identity oAuth2 provider.

* Configuration
```
Ping20Api_API_KEY=YOUR_API_KEY
Ping20Api_API_SECRET=YOUR_API_SECRET
Ping20Api_SCOPE=openid email profile cms
Ping20Api_ORGANIZATION_URL=YOUR_PING_ORG_URL
Ping20Api_PROTECTED_RESOURCE_URL=YOUR_PING_ORG_URL/idp/userinfo.openid
Ping20Api_FIRST_NAME_PROP=given_name
Ping20Api_LAST_NAME_PROP=family_name
```

## RESTful end points

### com.dotcms.osgi.oauth.rest.JsonWebTokenResource
End point that allows to use an Oauth2 token to authenticate with dotCMS and to return a dotCMS token

```
curl -v -XPOST http://localhost:8080/api/v1/authentication/token \
-H "Content-Type:application/json" \
-d '{
    "oauthToken":"eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0.eyJzY29wZSI6WyJvcGVuaWQiLCJlbWFpbCIsInByb2ZpbGUiLCJjbXMiXSwiY2xpZW50X2lkX25hbWUiOiJkb3RjbXMiLCJzdWIiOiJwcmFzYW5uYSIsIk9yZ05hbWUiOiJCbGFoIiwiVXNlcm5hbWUiOiJwcmFzYW5uYSIsImhvdXNlIjoiQ01TIEFkbWluaXN0cmF0b3IiLCJlbWFpbCI6InVzZXIuMzc2QGV4YW1wbGUuY29tIiwiZXhwIjoxNTM5MjE3MzYzfQ.LuIWdade2G7_87BNPFzb7ZaZqaq0gV_a6-S316rjEmmcKH67nCmpcH9TXEdPIUkOsD7rDb8AQ8n6c9DgCcxg4QRJTkDQ53dDY4V0nxGJuBD-xCE4gmIQPmLDQ1lXNKWNvy_7X8DB4wiJxwnRA7J8qVAzitavWBPURXOCB_EtR9KL2_E8rkRDO6q7i906KAkjfmQh7cfY3_flgRbyv9igEv8PNh7N3KjX_f5o-BJ3-Ak86K-yenVDzmgdQWZeXIN_7HAn5BvK6eWAK_4bltbJzB-mZOxzhuIisoqFtgmbhC2Pq7cB1AS8bbGxMu65LIhZt7Z5zVxTpRN9O456LX9NKA",
    "oauthProvider":"com.dotcms.osgi.oauth.provider.Google20Api",
    "expirationDays": 10 
}'
```

---
---
# How to build this example
 
 To install all you need to do is build the JAR. to do this run
 `./gradlew jar`
 
 This will build two jars in the `build/libs` directory: a bundle fragment (in order to expose needed 3rd party libraries from dotCMS) and the plugin jar 
 
 * **To install this bundle:**
 
     Upload the bundle jars files using the dotCMS UI (*CMS Admin->Dynamic Plugins->Upload Plugin*).
 
 * **To uninstall this bundle:**
     
     Undeploy the bundle jars using the dotCMS UI (*CMS Admin->Dynamic Plugins->Undeploy*).


## Using the plugin
To use this plugin, you will need to have a developer account with the authentication providers and an application registered with those providers.  In each application, make sure you: 
* Authorize the application scopes required by the plugin
* Authorize the Callback host to receive the callback.
* Copy the application API key and API secret and set them in the `oauth.properties` file.

This plugin intercepts the urls dotCMS uses to login (both front and backend) and points them to the OAuth provider specified.  You can see and or add/delete/modify the intercepted urls in the following classes modifying the `getFilters` methods on each of them:  

* https://github.com/dotCMS/plugin-dotcms-oauth/blob/master/src/main/java/com/dotcms/osgi/oauth/interceptor/LoginRequiredOAuthInterceptor.java#L61
* https://github.com/dotCMS/plugin-dotcms-oauth/blob/master/src/main/java/com/dotcms/osgi/oauth/interceptor/OAuthCallbackInterceptor.java#L77
* https://github.com/dotCMS/plugin-dotcms-oauth/blob/master/src/main/java/com/dotcms/osgi/oauth/interceptor/LogoutOAuthInterceptor.java#L40

If you want to avoid using oauth and authenticate via the standard dotCMS authentication, you can pass the url parameter `native=true` like this:

````
http://localhost:8080/html/portal/login.jsp?native=true 
````
or 
````
http://localhost:8080/dotCMS/login?native=true 
````

It is possible to use the oAuth2 providers in two ways:
1. Setting a `DEFAULT_OAUTH_PROVIDER` in order to use it automatically when authentication is required.
2. Specifying directly the provider to use, for example:
```
<a href="/dotCMS/login?referrer=/intranet/&OAUTH_PROVIDER=com.dotcms.osgi.oauth.provider.Facebook20Api" class="btn btn-lg btn-facebook"><i class="fa fa-facebook-square"></i> Login with Facebook</a>  
                    
<a href="/dotCMS/login?referrer=/intranet/&OAUTH_PROVIDER=com.dotcms.osgi.oauth.provider.Google20Api" class="btn btn-lg btn-google"><i class="fa fa-google-plus-square"></i> Login with Google+</a>
```
See the `examples/account-login.vtl` as reference.

## Configuration
In order to use this plugin you need to have a provider oAuth2 class (we provide 4 in this plugin, Google, Facebook, Okta and Ping identity) but it is possible to create custom oAuth2 providers if necessary but the `scribe` library already provides multiple providers that are ready to be use, for a list of those providers please refer to their documentation and examples: https://github.com/scribejava/scribejava 

### Custom oAuth2 Provider
Any oAuth2 provider must extend from `org.scribe.builder.api.DefaultApi20` and implement the `com.dotcms.osgi.oauth.provider.DotProvider` interface, the `com.dotcms.osgi.oauth.provider.DotProvider` interface is only required if you want to provide a revoke token url to be use on the dotCMS logout in order to revoke the generate authentication token.

The `org.scribe.builder.api.DefaultApi20` allows the developer to override methods required for the authentication process like `String getAccessTokenEndpoint()` in order to get the provider url to request the authentication access token or `String getAuthorizationUrl` to get the provider url for the initial authentication window.

Also allows to define a custom `org.scribe.oauth.OAuthService` in case of special handling is required, a good example is the `com.dotcms.osgi.oauth.provider.Ping20Api` class.

### Custom oAuth2 Service
Any oAuth2 service must extend from `org.scribe.oauth.OAuth20ServiceImpl` and implement the `com.dotcms.osgi.oauth.service.DotService` interface, the `com.dotcms.osgi.oauth.service.DotService` interface is only required if the user want to handle the revoke of an authentication token and in case that is required and/or apply to execute extra calls in order to get the user groups/roles in the authentication service. 

A good example is the `com.dotcms.osgi.oauth.provider.Ping20Api` class.

### oauth2.properties
In this file we are going to define most of the properties required to use this plugin and each of the oAuth2 providers, each property is explained in the properties file but it is important to notice that exist specific properties for each provider where the prefix of each property will be the name of the oAuth2 provider class, for example, is we have a custom provider `com.dotcms.osgi.oauth.provider.MyCustom20ApiProvider` the properties for that provider should use the `MyCustom20ApiProvider_` prefix:

    ```
    MyCustom20ApiProvider_API_KEY=YOUR_APPLICATION_KEY
    MyCustom20ApiProvider_API_SECRET=YOUR_APPLICATION_SECRET_KEY
    MyCustom20ApiProvider_SCOPE=email user_about_me
    MyCustom20ApiProvider_PROTECTED_RESOURCE_URL=https://www.example.com/oauth2/v2/userinfo
    MyCustom20ApiProvider_FIRST_NAME_PROP=first_name
    MyCustom20ApiProvider_LAST_NAME_PROP=last_name
    ```
    
---
---
# Plugin authentication flow
Simple explanation of the authentication flow handle by this plugin:

1. The `com.dotcms.osgi.oauth.interceptor.LoginRequiredOAuthInterceptor` identifies a resource requires authentication.
2. The user is redirected to the selected provider authentication page, that authentication page url is defined in the provider class.
3. The user is authenticated with the oAuth2 service.
4. The oAuth2 service generates an authentication code and the user is redirected back to dotCMS, to the defined `CALLBACK_URL` in the `oauth2.properties`.
5. The `com.dotcms.osgi.oauth.interceptor.OAuthCallbackInterceptor` intercepts the call back request, reads the authorization code and starts with the authentication process in dotCMS:
    1. Request the access token with the authentication code, the access token is the one that allow us to call restricted end points in order to request the user information and it is defined in the provider class.
    2. With the token we call the restricted end point configured in the `oauth2.properties` example: `MyCustom20ApiProvider_PROTECTED_RESOURCE_URL=https://www.example.com/oauth2/v2/userinfo`.
    3. We read the user information returned by that restricted end point: email, first and last name.
    4. With the email we validate if the user already exist in dotCMS, if not we create it.
    5. Some oAuth2 providers allow the configuration of groups/roles for the user and it is possible to map those groups to existing dotCMS roles in order to associate them to the user, to do that it is required to implement the `getGroups` method in the `com.dotcms.osgi.oauth.service.DotService` interface. The `com.dotcms.osgi.oauth.provider.Okta20Api` and `com.dotcms.osgi.oauth.provider.Ping20Api` are excellent examples of it.
    6. Also by default we associate to the user the dotCMS role defined in the `ROLES_TO_ADD` property of the `oauth2.properties`.
    7. Finally the user is authenticated to dotCMS.
6. If the user logout from dotCMS the `com.dotcms.osgi.oauth.interceptor.LogoutOAuthInterceptor` intercepts that request and tries to revoke the authentication token generated by the oAuth2 service (if a revoke url exist, not mandatory) before to execute the regular dotCMS logout process. 
