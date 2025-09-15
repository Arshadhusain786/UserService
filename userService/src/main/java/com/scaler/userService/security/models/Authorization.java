package com.scaler.userService.security.models;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;

import java.time.Instant;

@Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class Authorization {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private String id;

    private String registeredClientId;
    private String principalName;
    private String authorizationGrantType;
    private String authorizedScopes;

    @Column(columnDefinition = "text")
    private String attributes;

    private String state;

    private String authorizationCodeValue;
    private Instant authorizationCodeIssuedAt;
    private Instant authorizationCodeExpiresAt;

    @Column(columnDefinition = "text")
    private String authorizationCodeMetadata;

    private String accessTokenValue;
    private Instant accessTokenIssuedAt;
    private Instant accessTokenExpiresAt;

    @Column(columnDefinition = "text")
    private String accessTokenMetadata;

    private String accessTokenType;
    private String accessTokenScopes;

    private String refreshTokenValue;
    private Instant refreshTokenIssuedAt;
    private Instant refreshTokenExpiresAt;

    @Column(columnDefinition = "text")
    private String refreshTokenMetadata;

    private String oidcIdTokenValue;
    private Instant oidcIdTokenIssuedAt;
    private Instant oidcIdTokenExpiresAt;

    @Column(columnDefinition = "text")
    private String oidcIdTokenMetadata;

    @Column(columnDefinition = "text")
    private String oidcIdTokenClaims;

    private String userCodeValue;
    private Instant userCodeIssuedAt;
    private Instant userCodeExpiresAt;

    @Column(columnDefinition = "text")
    private String userCodeMetadata;

    private String deviceCodeValue;
    private Instant deviceCodeIssuedAt;
    private Instant deviceCodeExpiresAt;

    @Column(columnDefinition = "text")
    private String deviceCodeMetadata;

    @CreatedDate
    private Instant createdAt;

    @LastModifiedDate
    private Instant updatedAt;

}
