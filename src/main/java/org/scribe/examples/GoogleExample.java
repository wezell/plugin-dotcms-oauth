package org.scribe.examples;

import java.util.*;

import org.scribe.builder.*;
import org.scribe.builder.api.*;
import org.scribe.model.*;
import org.scribe.oauth.*;

public class GoogleExample
{

  private static  String PROTECTED_RESOURCE_URL = "https://www.googleapis.com/oauth2/v2/userinfo";
  private static  String SCOPE = "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile"; 
  private static  String API_KEY="507045234081-b2m9gr46dl0n8526n80tk377obbi3nb5.apps.googleusercontent.com";
  private static  String API_SECRET = "IyRAJXtxbHHT92ibIUdUJKDs";
  private static  String callback = "https://dotcms.com/app/oauthCallback";
  
  
  public static void main(String[] args)
  {
    OAuthService service = new ServiceBuilder()
                                  .provider(Google2Api.class)
                                  .apiKey(API_KEY)
                                  .apiSecret(API_SECRET)
                                  .scope(SCOPE)
                                  .callback(callback)
                                  .build();
    Scanner in = new Scanner(System.in);



    // Obtain the Authorization URL
    System.out.println("Fetching the Authorization URL...");
    String authorizationUrl = service.getAuthorizationUrl(null);
    System.out.println("Got the Authorization URL!");
    System.out.println("Now go and authorize Scribe here:");
    System.out.println(authorizationUrl);
    System.out.println("And paste the authorization code here");
    System.out.print(">>");
    Verifier verifier = new Verifier(in.nextLine());
    System.out.println();
    
    // Trade the Request Token and Verfier for the Access Token
    System.out.println("Trading the Request Token for an Access Token...");
    Token accessToken = service.getAccessToken(null, verifier);
    System.out.println("Got the Access Token!");
    System.out.println("(if your curious it looks like this: " + accessToken + " )");
    System.out.println();

    // Now let's go and ask for a protected resource!
    System.out.println("Now we're going to access a protected resource...");
    OAuthRequest request = new OAuthRequest(Verb.GET, PROTECTED_RESOURCE_URL);
    service.signRequest(accessToken, request);
    Response response = request.send();
    System.out.println("Got it! Lets see what we found...");
    System.out.println();
    System.out.println(response.getCode());
    System.out.println(response.getBody());

    System.out.println();
    System.out.println("Thats it man! Go and build something awesome with Scribe! :)");

  }
}