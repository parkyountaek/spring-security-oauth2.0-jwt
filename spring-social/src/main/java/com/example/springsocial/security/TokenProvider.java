package com.example.springsocial.security;

import java.util.Date;

import com.example.springsocial.config.AppProperties;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class TokenProvider {

  private AppProperties appProperties;

  public TokenProvider(AppProperties appProperties) {
      this.appProperties = appProperties;
  }

  public String createToken(Authentication authentication) {
      UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

      Date now = new Date();
      Date expiryDate = new Date(now.getTime() + appProperties.getAuth().getTokenExpirationMsec());

      return Jwts.builder()
              .setSubject(Long.toString(userPrincipal.getId()))
              .setIssuedAt(new Date())
              .setExpiration(expiryDate)
              .signWith(SignatureAlgorithm.HS512, appProperties.getAuth().getTokenSecret())
              .compact();
  }

  public Long getUserIdFromToken(String token) {
      Claims claims = Jwts
              .parserBuilder()
              .setSigningKey(appProperties.getAuth().getTokenSecret())
              .build()
              .parseClaimsJws(token)
              .getBody();

      return Long.parseLong(claims.getSubject());
  }

  public boolean validateToken(String authToken) {
    try {
        Jwts.parserBuilder().setSigningKey(appProperties.getAuth().getTokenSecret()).build().parseClaimsJws(authToken);
        return true;
    } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
        log.error("Invalid JWT signature");
    } catch (ExpiredJwtException ex) {
        log.error("Expired JWT token");
    } catch (UnsupportedJwtException ex) {
        log.error("Unsupported JWT token");
    } catch (IllegalArgumentException ex) {
        log.error("JWT claims string is empty.");
    }
    return false;
  }
}
