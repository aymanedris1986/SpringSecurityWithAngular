package dev.javarush.authorizationserver.grant.password;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.security.Principal;
import java.util.Set;

/**
 * =====================================================================================
 * RESOURCE OWNER PASSWORD AUTHENTICATION PROVIDER
 * =====================================================================================
 *
 * The core logic for the "password" grant type. This provider:
 *   1. Validates the client is authorized to use the "password" grant
 *   2. Authenticates the user via UserDetailsService + PasswordEncoder
 *   3. Generates JWT access token and refresh token using the authorization server's
 *      token generator (same pipeline as authorization_code and client_credentials)
 *   4. Stores the authorization in OAuth2AuthorizationService (enabling token
 *      introspection and revocation)
 *   5. Returns an OAuth2AccessTokenAuthenticationToken — the framework serializes
 *      this into the standard OAuth 2.0 token response
 *
 * ── Why this is different from the custom AuthController ──
 *   The previous REST controller was a completely separate authentication path. This
 *   provider plugs into the SAME /oauth2/token endpoint and uses the SAME token
 *   generation pipeline. The response is the standard OAuth 2.0 JSON:
 *     {
 *       "access_token": "eyJ...",
 *       "refresh_token": "abc...",
 *       "token_type": "Bearer",
 *       "expires_in": 300,
 *       "scope": "openid profile"
 *     }
 */
public class ResourceOwnerPasswordAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    public ResourceOwnerPasswordAuthenticationProvider(
            UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder,
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        ResourceOwnerPasswordAuthenticationToken passwordAuthentication =
                (ResourceOwnerPasswordAuthenticationToken) authentication;

        // ── Step 1: Validate the client ──
        // The client has already been authenticated by the framework (Basic auth header).
        // We just verify the client is allowed to use the "password" grant type.
        OAuth2ClientAuthenticationToken clientPrincipal =
                getAuthenticatedClientElseThrowInvalidClient(passwordAuthentication);
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        if (registeredClient == null ||
                !registeredClient.getAuthorizationGrantTypes()
                        .contains(ResourceOwnerPasswordAuthenticationToken.PASSWORD)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        // ── Step 2: Authenticate the resource owner ──
        // Use the SAME UserDetailsService and PasswordEncoder from UserManagementConfig.
        UserDetails user;
        try {
            user = userDetailsService.loadUserByUsername(passwordAuthentication.getUsername());
        } catch (UsernameNotFoundException e) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "Invalid user credentials", null));
        }

        if (!passwordEncoder.matches(
                (String) passwordAuthentication.getCredentials(), user.getPassword())) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "Invalid user credentials", null));
        }

        // ── Step 3: Determine authorized scopes ──
        // If the client didn't request specific scopes, grant all registered scopes.
        Set<String> authorizedScopes = passwordAuthentication.getScopes().isEmpty()
                ? registeredClient.getScopes()
                : passwordAuthentication.getScopes();

        // Ensure requested scopes are within the client's allowed scopes
        if (!registeredClient.getScopes().containsAll(authorizedScopes)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
        }

        // ── Step 4: Build the authenticated principal for token claims ──
        Authentication principal = new UsernamePasswordAuthenticationToken(
                user.getUsername(), null, user.getAuthorities());

        // ── Step 5: Generate access token ──
        // Uses the SAME token generator as authorization_code and client_credentials grants.
        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(principal)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizedScopes(authorizedScopes)
                .authorizationGrantType(ResourceOwnerPasswordAuthenticationToken.PASSWORD)
                .authorizationGrant(passwordAuthentication);

        OAuth2TokenContext tokenContext = tokenContextBuilder
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .build();

        OAuth2Token generatedAccessToken = tokenGenerator.generate(tokenContext);
        if (generatedAccessToken == null) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                            "Failed to generate access token.", null));
        }

        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                generatedAccessToken.getTokenValue(),
                generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt(),
                authorizedScopes);

        // ── Step 6: Build the authorization record ──
        // Storing this allows token introspection (/oauth2/introspect) and
        // revocation (/oauth2/revoke) to work for tokens issued via this grant.
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization
                .withRegisteredClient(registeredClient)
                .principalName(user.getUsername())
                .authorizationGrantType(ResourceOwnerPasswordAuthenticationToken.PASSWORD)
                .authorizedScopes(authorizedScopes)
                .attribute(Principal.class.getName(), principal);

        if (generatedAccessToken instanceof ClaimAccessor) {
            authorizationBuilder.token(accessToken, (metadata) ->
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                            ((ClaimAccessor) generatedAccessToken).getClaims()));
        } else {
            authorizationBuilder.accessToken(accessToken);
        }

        // ── Step 7: Generate refresh token (if the client supports it) ──
        OAuth2RefreshToken refreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes()
                .contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            tokenContext = tokenContextBuilder
                    .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                    .build();
            OAuth2Token generatedRefreshToken = tokenGenerator.generate(tokenContext);
            if (generatedRefreshToken != null) {
                refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
                authorizationBuilder.refreshToken(refreshToken);
            }
        }

        // ── Step 8: Save and return ──
        OAuth2Authorization authorization = authorizationBuilder.build();
        authorizationService.save(authorization);

        // The framework serializes this into the standard OAuth 2.0 token response JSON
        return new OAuth2AccessTokenAuthenticationToken(
                registeredClient, clientPrincipal, accessToken, refreshToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return ResourceOwnerPasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(
            Authentication authentication) {
        OAuth2ClientAuthenticationToken clientPrincipal = null;
        if (authentication.getPrincipal() instanceof OAuth2ClientAuthenticationToken token) {
            clientPrincipal = token;
        }
        if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
            return clientPrincipal;
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }
}
