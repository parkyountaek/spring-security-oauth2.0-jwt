package com.example.springsocial.security;

import java.security.Key;
import java.util.Date;

import com.example.springsocial.config.AppProperties;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class TokenProvider {

  private final AppProperties appProperties;
  private final Key key;

  public TokenProvider(AppProperties appProperties) {
    this.appProperties = appProperties;
    byte[] keyBytes = Decoders.BASE64.decode(appProperties.getAuth().getTokenSecret());
    this.key = Keys.hmacShaKeyFor(keyBytes);
  }
  public String createToken(Authentication authentication) {
    UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

    Date now = new Date();
    Date expiryDate = new Date(now.getTime() + appProperties.getAuth().getTokenExpirationMsec());

    return Jwts.builder()
            .setSubject(Long.toString(userPrincipal.getId()))
            .setIssuedAt(new Date())
            .setExpiration(expiryDate)
            .signWith(key, SignatureAlgorithm.HS512)
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
