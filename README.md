plugins-dotcms-oauth
====================

This is an osgi plugin that provides single sign-on using OAuth2.  This intended to be a drop in replacement for the standard dotcms login, both for front end users and for backend users and effectivly disables the out of the box authentication.

It provides a Google and a Facebook implementation. 


To use this plugin, you will need to have a developer account with the providers (Google, Facebook) and a application registered with the providers.  In each application, make sure you authorize the application scopes required by the plugin.  See the oauth.properties for the required scopes.



