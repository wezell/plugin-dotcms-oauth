plugins-dotcms-oauth
====================

This is an osgi plugin that provides single sign-on using OAuth2.  This intended to be a drop in replacement for the standard dotcms login, both for front end users and for backend users and effectivly disables the out of the box authentication.

It provides a Google and a Facebook implementation. 
* https://developers.google.com/accounts/docs/OAuth2
* https://developers.facebook.com/docs/facebook-login/v2.1

To use this plugin, you will need to have a developer account with the providers (Google, Facebook) and a application registered with the providers.  In each application, make sure you: 
* Authorize the application scopes required by the plugin
* Authorize the Callback host to receive the callback.
* Copy the application API key and API secret and set them in the oauth.properties file.

See the oauth.properties for the required scopes.



