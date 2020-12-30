package com.dotcms.osgi.oauth.app;

public enum AppKeys {
        ENABLE_BACKEND("enableBackend"),
        ENABLE_FRONTEND("enableFrontend"),
        PROVIDER("provider"),
        API_KEY("apiKey"),
        API_SECRET("apiSecret"),
        SCOPE("scope"),
        PROTECTED_RESOURCE("protectedResource"),
        GROUP_RESOURCE("groupResource"),
        ;


       final public String key;
        
       AppKeys(String key){
            this.key=key;
        }
        
    
       public final static String APP_KEY = "dotOAuthApp";
       
       public final static String APP_YAML_NAME = APP_KEY + ".yml";
       
       
       
}
