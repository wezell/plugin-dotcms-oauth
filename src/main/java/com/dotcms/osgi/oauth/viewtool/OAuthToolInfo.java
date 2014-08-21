package com.dotcms.osgi.oauth.viewtool;

import org.apache.velocity.tools.view.context.ViewContext;
import org.apache.velocity.tools.view.servlet.ServletToolInfo;

public class OAuthToolInfo extends ServletToolInfo {

    @Override
    public String getKey () {
        return "oauthtool";
    }

    @Override
    public String getScope () {
        return ViewContext.APPLICATION;
    }

    @Override
    public String getClassname () {
        return OAuthTool.class.getName();
    }

    @Override
    public Object getInstance ( Object initData ) {

    	OAuthTool viewTool = new OAuthTool();
        viewTool.init( initData );

        setScope( ViewContext.APPLICATION );

        return viewTool;
    }

}