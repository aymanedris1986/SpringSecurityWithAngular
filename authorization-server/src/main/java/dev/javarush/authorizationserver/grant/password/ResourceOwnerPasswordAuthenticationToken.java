package dev.javarush.authorizationserver.grant.password;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * =====================================================================================
 * RESOURCE OWNER PASSWORD AUTHENTICATION TOKEN
 * =====================================================================================
 *
 * Represents the authentication request for the "password" grant type.
 * This token carries the resource owner's (user's) credentials — username and password —
 * along with the already-authenticated client principal.
 *
 * ── OAuth 2.0 Principle ──
 *   The Resource Owner Password Credentials grant (RFC 6749 §4.3) allows the client to
 *   exchange the user's credentials directly for tokens. While removed from OAuth 2.1,
 *   it remains useful for first-party applications where the client is fully trusted.
 *
 * ── Flow ──
 *   1. ResourceOwnerPasswordAuthenticationConverter creates this token from the HTTP request
 *   2. ResourceOwnerPasswordAuthenticationProvider validates it and produces tokens
 */
public class ResourceOwnerPasswordAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    /**
     * The custom grant type identifier — "password".
     */
    public static final AuthorizationGrantType PASSWORD = new AuthorizationGrantType("password");

    private final String username;
    private final String password;
    private final Set<String> scopes;

    public ResourceOwnerPasswordAuthenticationToken(
            Authentication clientPrincipal,
            String username,
            String password,
            @Nullable Set<String> scopes,
            @Nullable Map<String, Object> additionalParameters) {
        super(PASSWORD, clientPrincipal, additionalParameters);
        this.username = username;
        this.password = password;
        this.scopes = scopes != null ? Collections.unmodifiableSet(scopes) : Collections.emptySet();
    }

    public String getUsername() {
        return username;
    }

    @Override
    public Object getCredentials() {
        return password;
    }

    public Set<String> getScopes() {
        return scopes;
    }
}
