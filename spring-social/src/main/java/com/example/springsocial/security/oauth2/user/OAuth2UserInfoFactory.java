package com.example.springsocial.security.oauth2.user;

import java.util.Map;

import com.example.springsocial.domain.AuthProvider;
import com.example.springsocial.exception.OAuth2AuthenticationProcessingException;

public class OAuth2UserInfoFactory {
  public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
    if(registrationId.equalsIgnoreCase(AuthProvider.google.toString())) {
      return new GoogleOAuth2UserInfo(attributes);
    } else {
      throw new OAuth2AuthenticationProcessingException("Sorry! Login with " + registrationId + " is not supported yet.");
    }
  }
}
