package dev.javarush.authorizationserver.config;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import dev.javarush.authorizationserver.grant.password.ResourceOwnerPasswordAuthenticationConverter;
import dev.javarush.authorizationserver.grant.password.ResourceOwnerPasswordAuthenticationProvider;
import dev.javarush.authorizationserver.grant.password.ResourceOwnerPasswordAuthenticationToken;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

/**
 * =====================================================================================
 * AUTHORIZATION SERVER CONFIGURATION
 * =====================================================================================
 *
 * This class configures the Spring Authorization Server — the central component in the
 * OAuth 2.0 / OpenID Connect (OIDC) architecture. It acts as the "trusted authority"
 * that issues access tokens, ID tokens, and refresh tokens to registered clients
 * after successfully authenticating the Resource Owner (the user).
 *
 * ── OAuth 2.0 Roles Involved ──
 *   • Authorization Server  → THIS application (issues tokens)
 *   • Client                → The Angular / SPA application that wants to access protected resources
 *   • Resource Owner        → The end user who grants permission
 *   • Resource Server       → The backend API that validates tokens and serves data
 *
 * ── Overall Flow (Authorization Code Grant) ──
 *   1. Client redirects user to this Authorization Server's /authorize endpoint.
 *   2. This server authenticates the user (via the login form, see UserManagementConfig).
 *   3. User consents to the requested scopes (openid, profile, etc.).
 *   4. This server redirects back to the Client's redirect URI with an authorization code.
 *   5. Client exchanges the code for tokens at the /oauth2/token endpoint.
 *   6. This server validates the client credentials and returns access/refresh/ID tokens.
 *   7. Client uses the access token to call the Resource Server.
 *
 * ── Bean Ordering & Interaction ──
 *   This config defines 3 beans that work together:
 *     [1] authorizationServerSecurityFilterChain  — HTTP security for OAuth 2.0 endpoints
 *     [2] registeredClientRepository              — The "who is allowed to request tokens"
 *     [3] authorizationServerSettings             — Endpoint URIs & issuer metadata
 */
@Configuration
public class AuthorizationServerConfig {

    /**
     * ─────────────────────────────────────────────────────────────────────────────────
     * BEAN 1 — Authorization Server Security Filter Chain
     * ─────────────────────────────────────────────────────────────────────────────────
     *
     * FLOW ORDER: ★ This is the FIRST filter chain evaluated (Order = 1).
     *
     * PURPOSE:
     *   Configures the HTTP security specifically for the OAuth 2.0 / OIDC protocol
     *   endpoints exposed by the Authorization Server. These include:
     *     • /oauth2/authorize       — Authorization Endpoint (user consent & code issuance)
     *     • /oauth2/token           — Token Endpoint (code → token exchange)
     *     • /oauth2/jwks            — JWK Set Endpoint (public keys for token verification)
     *     • /oauth2/revoke          — Token Revocation Endpoint
     *     • /oauth2/introspect      — Token Introspection Endpoint
     *     • /.well-known/openid-configuration  — OIDC Discovery Endpoint
     *
     * WHY @Order(1)?
     *   Spring Security can have multiple SecurityFilterChain beans. They are matched
     *   in order; the FIRST chain whose request matcher matches the incoming request
     *   is used. This chain is @Order(1) so that OAuth 2.0 protocol requests (like
     *   /oauth2/token) are handled HERE, before falling through to the more generic
     *   user-management filter chain (@Order(2) in UserManagementConfig).
     *
     * OAUTH 2.0 PRINCIPLE:
     *   The Authorization Server MUST expose well-defined protocol endpoints that
     *   clients can discover and interact with. This method sets up all those
     *   endpoints with their default security rules (e.g., /oauth2/token requires
     *   client authentication, /oauth2/authorize requires user authentication).
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder,
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator
    ) throws Exception {

        /*
         * STEP 1 — Apply Default OAuth 2.0 Authorization Server Security
         *
         * This single call registers all the OAuth 2.0 protocol endpoints listed
         * above and configures:
         *   • Request matchers so this filter chain ONLY handles OAuth 2.0 requests
         *   • Client authentication filters (to validate client_id / client_secret)
         *   • Token generation and validation logic
         *   • CSRF protection tailored for the authorization server
         *
         * Under the hood it applies the OAuth2AuthorizationServerConfigurer with
         * sensible defaults so you don't have to wire each endpoint manually.
         */
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        /*
         * STEP 2 — Enable OIDC + Register the custom "password" grant type
         *
         * The tokenEndpoint customization registers:
         *   • ResourceOwnerPasswordAuthenticationConverter — parses grant_type=password
         *     requests from the /oauth2/token endpoint
         *   • ResourceOwnerPasswordAuthenticationProvider — validates user credentials
         *     and generates tokens through the SAME token pipeline as other grants
         *
         * This means the client calls the SAME /oauth2/token endpoint with:
         *   grant_type=password&username=<user>&password=<pass>
         * and gets back the standard OAuth 2.0 token response.
         */
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .tokenEndpoint(tokenEndpoint -> tokenEndpoint
                        .accessTokenRequestConverter(
                                new ResourceOwnerPasswordAuthenticationConverter())
                        .authenticationProvider(
                                new ResourceOwnerPasswordAuthenticationProvider(
                                        userDetailsService,
                                        passwordEncoder,
                                        authorizationService,
                                        tokenGenerator))
                )
                .oidc(Customizer.withDefaults());

        /*
         * STEP 3 — Configure the Authentication Entry Point (redirect to login)
         *
         * PROBLEM THIS SOLVES:
         *   When an unauthenticated user (or browser) hits the /oauth2/authorize
         *   endpoint, they need to be redirected to a login page so they can
         *   authenticate first. Without this, they'd get a raw 401/403 error.
         *
         * HOW IT WORKS:
         *   • LoginUrlAuthenticationEntryPoint("/login") → redirect unauthenticated
         *     users to the /login page (served by the form login in UserManagementConfig)
         *   • MediaTypeRequestMatcher(TEXT_HTML) → only apply this redirect for
         *     browser requests (Accept: text/html). API/JSON requests will still
         *     receive a proper 401 response so programmatic clients aren't broken.
         *
         * OAUTH 2.0 PRINCIPLE:
         *   In the Authorization Code flow, user authentication is a PREREQUISITE
         *   before the authorization server can issue an authorization code. This
         *   entry point ensures the user is sent to authenticate (login form) before
         *   being returned to the authorization endpoint to complete the flow.
         */
        http.exceptionHandling(c -> c
                .defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
        );

        return http.build();
    }

    /**
     * ─────────────────────────────────────────────────────────────────────────────────
     * BEAN 2 — Registered Client Repository
     * ─────────────────────────────────────────────────────────────────────────────────
     *
     * FLOW ORDER: ★ Used during STEPS 1 and 5 of the Authorization Code flow.
     *   • Step 1 — When the client redirects the user to /oauth2/authorize, the server
     *              looks up the client_id in this repository to validate that the
     *              client is registered and the redirect_uri matches.
     *   • Step 5 — When the client exchanges the authorization code for tokens at
     *              /oauth2/token, the server authenticates the client by looking up
     *              its credentials (client_id + client_secret) from this repository.
     *
     * PURPOSE:
     *   Defines WHICH clients (applications) are allowed to request tokens from this
     *   Authorization Server. In OAuth 2.0, every client must be pre-registered with
     *   the authorization server. This is the "client registration" concept.
     *
     * OAUTH 2.0 PRINCIPLE — Client Registration (RFC 6749 §2):
     *   Before an OAuth 2.0 client can make authorization requests, it must be
     *   registered with the authorization server. Registration includes:
     *     • A unique client identifier (client_id)
     *     • Client credentials (client_secret) for confidential clients
     *     • Allowed grant types
     *     • Allowed redirect URIs
     *     • Allowed scopes
     *
     * NOTE: InMemoryRegisteredClientRepository is for development/demo purposes.
     *       In production, use a JdbcRegisteredClientRepository backed by a database.
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient client = RegisteredClient.withId("1")

                /*
                 * CLIENT_ID — The public identifier for this client application.
                 * Sent in the /oauth2/authorize request as a query parameter and
                 * in the /oauth2/token request for client authentication.
                 */
                .clientId("client")

                /*
                 * CLIENT_SECRET — The confidential credential for this client.
                 * Used to authenticate the client at the /oauth2/token endpoint.
                 * ⚠️ WARNING: In production, this MUST be encoded (e.g., BCrypt).
                 *    Plain text secrets are only acceptable for local development.
                 */
                .clientSecret("secret")

                /*
                 * AUTHORIZATION GRANT TYPES — Define HOW the client can obtain tokens.
                 *
                 * 1) AUTHORIZATION_CODE (RFC 6749 §4.1):
                 *    The most secure and recommended flow for web/mobile apps.
                 *    Flow: User authenticates → gets auth code → client exchanges
                 *    code for tokens. The access token is NEVER exposed to the browser.
                 *
                 * 2) CLIENT_CREDENTIALS (RFC 6749 §4.4):
                 *    Machine-to-machine (M2M) flow — no user involved.
                 *    The client authenticates directly with its own credentials
                 *    to get an access token. Used for backend service-to-service calls.
                 *
                 * 3) REFRESH_TOKEN (RFC 6749 §6):
                 *    Allows the client to obtain a NEW access token without requiring
                 *    the user to re-authenticate. The refresh token is exchanged for
                 *    a fresh access token when the current one expires.
                 */
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(ResourceOwnerPasswordAuthenticationToken.PASSWORD)

                /*
                 * CLIENT AUTHENTICATION METHOD — How the client proves its identity
                 * at the token endpoint.
                 *
                 * CLIENT_SECRET_BASIC (RFC 6749 §2.3.1):
                 *   The client sends its credentials as an HTTP Basic Authorization
                 *   header: Authorization: Basic base64(client_id:client_secret)
                 *   This is preferred over CLIENT_SECRET_POST because credentials
                 *   travel in headers rather than the request body.
                 */
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)

                /*
                 * SCOPES — Define WHAT the client is allowed to access.
                 *
                 * Scopes limit the access granted by an access token. The client
                 * requests scopes during authorization; the user can consent to
                 * all or a subset of them.
                 *
                 * • OPENID — Required for OIDC. Signals that this is an authentication
                 *   request. When present, the server issues an ID Token in addition
                 *   to the access token.
                 *
                 * • PROFILE — An OIDC standard scope that grants access to the user's
                 *   profile claims (name, family_name, picture, etc.) via the
                 *   UserInfo endpoint or as claims in the ID Token.
                 */
                .scope(OidcScopes.PROFILE)
                .scope(OidcScopes.OPENID)

                /*
                 * REDIRECT URI — Where the authorization server sends the user BACK
                 * after they authenticate and consent.
                 *
                 * OAUTH 2.0 PRINCIPLE (RFC 6749 §3.1.2):
                 *   The redirect URI MUST exactly match one of the pre-registered URIs.
                 *   This prevents "open redirect" attacks where an attacker could
                 *   intercept the authorization code by supplying a malicious URI.
                 *
                 * This URI points to the CLIENT application (running on port 8081)
                 * at the standard Spring Security OAuth2 login callback path. The
                 * authorization code is appended as a query parameter: ?code=xyz
                 */
                .redirectUri("http://localhost:8081/login/oauth2/code/client")
                .build();

        return new InMemoryRegisteredClientRepository(client);
    }

    /**
     * ─────────────────────────────────────────────────────────────────────────────────
     * BEAN 3 — Authorization Server Settings
     * ─────────────────────────────────────────────────────────────────────────────────
     *
     * FLOW ORDER: ★ Used at SERVER STARTUP and during OIDC Discovery.
     *
     * PURPOSE:
     *   Configures the Authorization Server's metadata — primarily the endpoint URIs
     *   and the issuer identifier. By calling .builder().build() with no customization,
     *   we accept all the default endpoint paths:
     *     • Authorization Endpoint:    /oauth2/authorize
     *     • Token Endpoint:            /oauth2/token
     *     • JWK Set Endpoint:          /oauth2/jwks
     *     • Token Revocation:          /oauth2/revoke
     *     • Token Introspection:       /oauth2/introspect
     *     • OIDC Discovery:            /.well-known/openid-configuration
     *
     * OAUTH 2.0 / OIDC PRINCIPLE:
     *   The OIDC Discovery document (RFC 8414 / OpenID Connect Discovery 1.0) allows
     *   clients to automatically discover all the endpoints and capabilities of the
     *   authorization server by fetching a single JSON document. This settings bean
     *   controls what goes into that discovery document.
     *
     * NOTE: In production you'd typically set the issuer URI explicitly:
     *       AuthorizationServerSettings.builder()
     *           .issuer("https://auth.yourdomain.com")
     *           .build();
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    /**
     * ─────────────────────────────────────────────────────────────────────────────────
     * BEAN 4 — OAuth2 Token Generator
     * ─────────────────────────────────────────────────────────────────────────────────
     *
     * Explicitly defines the token generator as a Spring bean so it can be:
     *   1. Used by the framework for authorization_code and client_credentials grants
     *   2. Injected into our custom ResourceOwnerPasswordAuthenticationProvider
     *
     * The generator delegates to three sub-generators in order:
     *   • JwtGenerator           — produces JWT access tokens (signed with the server's RSA key)
     *   • OAuth2AccessTokenGenerator — fallback for opaque access tokens
     *   • OAuth2RefreshTokenGenerator — produces opaque refresh tokens
     */
    @Bean
    public OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator(
            JWKSource<SecurityContext> jwkSource) {
        JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
        return new DelegatingOAuth2TokenGenerator(
                jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
    }

    /**
     * ─────────────────────────────────────────────────────────────────────────────────
     * BEAN 5 — OAuth2 Authorization Service
     * ─────────────────────────────────────────────────────────────────────────────────
     *
     * Stores OAuth2 authorizations (tokens, codes, etc.) in memory.
     * Defined explicitly because the filter chain depends on it at construction time.
     *
     * IN PRODUCTION: Replace with JdbcOAuth2AuthorizationService backed by a database.
     */
    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }

    /**
     * ─────────────────────────────────────────────────────────────────────────────────
     * BEAN 6 — OAuth2 Authorization Consent Service
     * ─────────────────────────────────────────────────────────────────────────────────
     *
     * Stores user consent decisions (which scopes the user approved) in memory.
     *
     * IN PRODUCTION: Replace with JdbcOAuth2AuthorizationConsentService.
     */
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService() {
        return new InMemoryOAuth2AuthorizationConsentService();
    }
}
