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
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.jdbc.core.JdbcTemplate;
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
 *
 * ── The Three Tokens: Access Token vs ID Token vs Refresh Token ──
 *
 *   When the client exchanges the authorization code at /oauth2/token (Step 5 above),
 *   the server may return UP TO THREE tokens in a single response. Each serves a
 *   completely different purpose. Confusing them is one of the most common OAuth 2.0
 *   mistakes — here's exactly what each one does:
 *
 *   ┌──────────────────────────────────────────────────────────────────────────────┐
 *   │                        1. ACCESS TOKEN (OAuth 2.0)                          │
 *   ├──────────────────────────────────────────────────────────────────────────────┤
 *   │                                                                             │
 *   │  SPEC:     RFC 6749 §1.4, RFC 9068 (JWT Profile for Access Tokens)          │
 *   │                                                                             │
 *   │  PURPOSE:  Authorization — "What can this client do?"                       │
 *   │            The access token is a CREDENTIAL that the client presents to the  │
 *   │            Resource Server to prove it has been authorized to access specific│
 *   │            resources on behalf of the user.                                  │
 *   │                                                                             │
 *   │  AUDIENCE: The RESOURCE SERVER (your backend API), NOT the client.           │
 *   │            The client treats it as an opaque bearer credential — it should   │
 *   │            NOT parse, decode, or rely on its contents.                       │
 *   │                                                                             │
 *   │  FORMAT:   Either a signed JWT or an opaque string. Spring Authorization    │
 *   │            Server uses JWT by default (via JwtGenerator), which lets the     │
 *   │            Resource Server validate the token locally without calling back   │
 *   │            to the Authorization Server.                                      │
 *   │                                                                             │
 *   │  TYPICAL CONTENTS (JWT):                                                    │
 *   │    {                                                                         │
 *   │      "sub": "java-rush",           // subject (the user)                    │
 *   │      "aud": "client",              // audience (the client_id)              │
 *   │      "iss": "http://localhost:9000",// issuer (this auth server)            │
 *   │      "scope": "openid profile",    // granted scopes                       │
 *   │      "exp": 1717200000,            // expiration (Unix timestamp)           │
 *   │      "iat": 1717196400             // issued at                             │
 *   │    }                                                                         │
 *   │                                                                             │
 *   │  LIFESPAN: Short-lived — typically 5 to 60 minutes. Short expiry limits     │
 *   │            the damage if the token is leaked.                                │
 *   │                                                                             │
 *   │  HOW IT'S USED:                                                             │
 *   │    Client → Resource Server: Authorization: Bearer <access_token>            │
 *   │    The Resource Server validates the signature, checks expiry and scopes,   │
 *   │    and serves (or denies) the requested data.                                │
 *   │                                                                             │
 *   │  SPRING EQUIVALENT:                                                         │
 *   │    Generated by JwtGenerator (or OAuth2AccessTokenGenerator for opaque).    │
 *   │    Stored in OAuth2Authorization via OAuth2AuthorizationService.             │
 *   └──────────────────────────────────────────────────────────────────────────────┘
 *
 *   ┌──────────────────────────────────────────────────────────────────────────────┐
 *   │                   2. ID TOKEN (OpenID Connect 1.0)                           │
 *   ├──────────────────────────────────────────────────────────────────────────────┤
 *   │                                                                             │
 *   │  SPEC:     OpenID Connect Core 1.0 §2                                       │
 *   │                                                                             │
 *   │  PURPOSE:  Authentication — "WHO is this user?"                             │
 *   │            The ID Token is a security token that contains claims about the   │
 *   │            authentication event and the user's identity. It proves that the  │
 *   │            user authenticated at a specific time using a specific method.     │
 *   │                                                                             │
 *   │  AUDIENCE: The CLIENT (your Angular/SPA app), NOT the Resource Server.       │
 *   │            The client parses and validates the ID Token to learn who the     │
 *   │            user is and to establish a local session.                          │
 *   │                                                                             │
 *   │  FORMAT:   ALWAYS a signed JWT — this is required by the OIDC spec. The     │
 *   │            client MUST validate the signature, issuer, audience, and expiry. │
 *   │                                                                             │
 *   │  TYPICAL CONTENTS:                                                          │
 *   │    {                                                                         │
 *   │      "iss": "http://localhost:9000",  // issuer                             │
 *   │      "sub": "java-rush",              // subject (unique user ID)           │
 *   │      "aud": "client",                 // audience (MUST match client_id)    │
 *   │      "iat": 1717196400,               // issued at                          │
 *   │      "exp": 1717200000,               // expiration                         │
 *   │      "auth_time": 1717196350,         // when the user actually logged in   │
 *   │      "nonce": "abc123",               // replay protection (from client)    │
 *   │      "name": "Java Rush",             // profile claim (if profile scope)   │
 *   │      "email": "java@rush.dev"         // email claim (if email scope)       │
 *   │    }                                                                         │
 *   │                                                                             │
 *   │  LIFESPAN: Short-lived — typically same as access token. After the client   │
 *   │            validates it and creates a session, it can be discarded.           │
 *   │                                                                             │
 *   │  KEY DIFFERENCES FROM ACCESS TOKEN:                                          │
 *   │    • Access Token = "the client is AUTHORIZED to access resources"           │
 *   │    • ID Token     = "this USER is AUTHENTICATED and their identity is X"    │
 *   │    • ⚠️ NEVER send the ID Token to the Resource Server as a bearer token.   │
 *   │      The ID Token is for the CLIENT to consume; the Access Token is for      │
 *   │      the Resource Server.                                                    │
 *   │                                                                             │
 *   │  WHEN IS IT ISSUED?                                                         │
 *   │    Only when the client requests the "openid" scope. If the "openid" scope  │
 *   │    is not included in the authorization request, no ID Token is issued and   │
 *   │    the flow is plain OAuth 2.0 (not OIDC).                                   │
 *   │                                                                             │
 *   │  SPRING EQUIVALENT:                                                         │
 *   │    Generated by the OidcIdTokenGenerator internally when OIDC is enabled    │
 *   │    (.oidc(Customizer.withDefaults())) and the "openid" scope is granted.    │
 *   └──────────────────────────────────────────────────────────────────────────────┘
 *
 *   ┌──────────────────────────────────────────────────────────────────────────────┐
 *   │                    3. REFRESH TOKEN (OAuth 2.0)                              │
 *   ├──────────────────────────────────────────────────────────────────────────────┤
 *   │                                                                             │
 *   │  SPEC:     RFC 6749 §1.5, §6                                                │
 *   │                                                                             │
 *   │  PURPOSE:  Token Renewal — "Get a new access token without re-login."       │
 *   │            When the access token expires, the client uses the refresh token  │
 *   │            to silently obtain a new access token (and optionally a new       │
 *   │            refresh token) WITHOUT requiring the user to log in again.         │
 *   │                                                                             │
 *   │  AUDIENCE: The AUTHORIZATION SERVER only. The refresh token is sent BACK     │
 *   │            to the /oauth2/token endpoint (grant_type=refresh_token) to get   │
 *   │            fresh tokens. It is NEVER sent to the Resource Server.             │
 *   │                                                                             │
 *   │  FORMAT:   Typically an opaque (random) string — not a JWT. Since it is only│
 *   │            consumed by the Authorization Server that issued it, there is no  │
 *   │            need for self-contained claims. The server looks it up in its     │
 *   │            internal store (OAuth2AuthorizationService).                       │
 *   │                                                                             │
 *   │  LIFESPAN: Long-lived — typically hours, days, or even weeks. It must       │
 *   │            outlive the access token, otherwise there's no benefit. Common    │
 *   │            configurations:                                                   │
 *   │              • Access token:  30 minutes                                     │
 *   │              • Refresh token: 7 days                                         │
 *   │                                                                             │
 *   │  SECURITY CONSIDERATIONS:                                                   │
 *   │    • Store securely — refresh tokens are high-value credentials. If leaked,  │
 *   │      an attacker can mint new access tokens until the refresh token expires  │
 *   │      or is revoked.                                                          │
 *   │    • Rotate on use — best practice is to issue a NEW refresh token each time│
 *   │      the old one is used (refresh token rotation), invalidating the old one. │
 *   │      Spring Authorization Server supports this via TokenSettings:            │
 *   │        .tokenSettings(TokenSettings.builder()                                │
 *   │            .reuseRefreshTokens(false)  // enable rotation                    │
 *   │            .build())                                                         │
 *   │    • For SPAs (public clients) — refresh tokens should be avoided or paired  │
 *   │      with additional security (e.g., sender-constrained tokens, or use the  │
 *   │      BFF pattern where the backend holds the tokens).                        │
 *   │                                                                             │
 *   │  THE REFRESH FLOW:                                                          │
 *   │    Client → Auth Server:  POST /oauth2/token                                │
 *   │                           grant_type=refresh_token                           │
 *   │                           refresh_token=<refresh_token>                      │
 *   │                           + client authentication (Basic header)             │
 *   │    Auth Server → Client:  { access_token, refresh_token, id_token (maybe) } │
 *   │                                                                             │
 *   │  SPRING EQUIVALENT:                                                         │
 *   │    Generated by OAuth2RefreshTokenGenerator. Stored and looked up via        │
 *   │    OAuth2AuthorizationService. Enabled when the client has the               │
 *   │    REFRESH_TOKEN grant type registered (see registeredClientRepository).      │
 *   └──────────────────────────────────────────────────────────────────────────────┘
 *
 *   ── Quick Comparison Table ──
 *
 *   ┌───────────────┬─────────────────┬─────────────────┬──────────────────────────┐
 *   │               │  ACCESS TOKEN   │    ID TOKEN      │    REFRESH TOKEN         │
 *   ├───────────────┼─────────────────┼─────────────────┼──────────────────────────┤
 *   │ Spec          │ OAuth 2.0       │ OpenID Connect  │ OAuth 2.0                │
 *   │ Purpose       │ Authorization   │ Authentication  │ Token renewal            │
 *   │ Audience      │ Resource Server │ Client app      │ Authorization Server     │
 *   │ Format        │ JWT or opaque   │ Always JWT      │ Opaque                   │
 *   │ Lifespan      │ Minutes         │ Minutes         │ Hours / days             │
 *   │ Sent to API?  │ ✅ Yes          │ ❌ Never        │ ❌ Never                 │
 *   │ Contains user │ Minimal (sub)   │ Rich identity   │ None (just a reference)  │
 *   │ Revocable?    │ Only at expiry* │ N/A (consumed)  │ ✅ Yes (server-side)     │
 *   └───────────────┴─────────────────┴─────────────────┴──────────────────────────┘
 *   * JWT access tokens can't truly be "revoked" since they're stateless. The server
 *     can use token introspection or short expiry + refresh to achieve similar results.
 *
 *   ── Common Mistakes to Avoid ──
 *
 *   ⚠️ 1. DON'T use the ID Token as an access token.
 *         The ID Token is for the CLIENT to know WHO the user is.
 *         The access token is for the RESOURCE SERVER to know WHAT is allowed.
 *
 *   ⚠️ 2. DON'T parse the access token in the client.
 *         The client should treat the access token as an opaque string. Its format
 *         and claims can change without notice (it's meant for the Resource Server).
 *
 *   ⚠️ 3. DON'T store refresh tokens in localStorage (for browser apps).
 *         Refresh tokens are long-lived and high-value. In SPAs, prefer the BFF
 *         (Backend-For-Frontend) pattern where refresh tokens stay on the server.
 *
 *   ⚠️ 4. DON'T skip the "openid" scope and expect an ID Token.
 *         The ID Token is ONLY issued when the "openid" scope is requested.
 *         Without it, you get plain OAuth 2.0 — no identity information.
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
                 * ─────────────────────────────────────────────────────────────
                 * SCOPES — Define WHAT the client is allowed to access
                 * ─────────────────────────────────────────────────────────────
                 *
                 * WHAT IS A SCOPE?
                 *   A scope is a permission label that limits what an access token
                 *   can do. Think of scopes as "permission slips":
                 *     • The CLIENT requests a set of scopes when redirecting the
                 *       user to /oauth2/authorize
                 *     • The USER sees these scopes on the CONSENT SCREEN and can
                 *       approve or deny each one
                 *     • The AUTHORIZATION SERVER issues an access token that
                 *       contains ONLY the approved scopes
                 *     • The RESOURCE SERVER checks the token's scopes before
                 *       serving data (e.g., "does this token have the 'email'
                 *       scope? If not, deny access to the email endpoint")
                 *
                 * In short: Scopes = what the CLIENT is allowed to ask for,
                 * filtered by what the USER agrees to share.
                 *
                 * ── THE 5 STANDARD OIDC SCOPES (OpenID Connect Core 1.0 §5.4) ──
                 *
                 * ┌────────────────────────────────────────────────────────────────────────┐
                 * │  1. openid  (REQUIRED for OIDC)                                       │
                 * ├────────────────────────────────────────────────────────────────────────┤
                 * │                                                                        │
                 * │  PURPOSE: Signals that this is an AUTHENTICATION request, not just     │
                 * │           an authorization request. It tells the Authorization Server  │
                 * │           "I want to know WHO the user is, not just get access."       │
                 * │                                                                        │
                 * │  WHAT IT UNLOCKS:                                                      │
                 * │    • The server issues an ID TOKEN alongside the access token          │
                 * │    • The ID Token contains the "sub" (subject) claim — the unique      │
                 * │      identifier of the authenticated user                              │
                 * │    • Enables the /userinfo endpoint for retrieving user claims          │
                 * │                                                                        │
                 * │  WITHOUT IT:                                                           │
                 * │    No ID Token is issued. The flow is plain OAuth 2.0 — the client     │
                 * │    gets an access token but has NO information about who the user is.   │
                 * │                                                                        │
                 * │  CLAIMS ADDED TO ID TOKEN:                                             │
                 * │    • sub       — unique user identifier (always present)               │
                 * │    • iss       — issuer URL                                            │
                 * │    • aud       — client_id                                             │
                 * │    • exp / iat — expiration / issued-at timestamps                     │
                 * │    • auth_time — when the user actually authenticated                  │
                 * │    • nonce     — replay protection value (if provided by client)       │
                 * │                                                                        │
                 * │  SPRING CONSTANT: OidcScopes.OPENID = "openid"                        │
                 * └────────────────────────────────────────────────────────────────────────┘
                 *
                 * ┌────────────────────────────────────────────────────────────────────────┐
                 * │  2. profile                                                            │
                 * ├────────────────────────────────────────────────────────────────────────┤
                 * │                                                                        │
                 * │  PURPOSE: Grants access to the user's basic profile information.       │
                 * │           This is the "tell me about yourself" scope.                  │
                 * │                                                                        │
                 * │  CLAIMS UNLOCKED (returned in ID Token and/or /userinfo):              │
                 * │    • name              — full display name ("Java Rush")               │
                 * │    • given_name        — first name ("Java")                           │
                 * │    • family_name       — last name ("Rush")                            │
                 * │    • middle_name       — middle name                                   │
                 * │    • nickname          — casual name or alias                          │
                 * │    • preferred_username— the username the user prefers                 │
                 * │    • profile           — URL to the user's profile page                │
                 * │    • picture           — URL to the user's avatar/photo                │
                 * │    • website           — URL to the user's personal website            │
                 * │    • gender            — gender                                        │
                 * │    • birthdate         — birthday (YYYY-MM-DD)                         │
                 * │    • zoneinfo          — timezone (e.g., "Europe/Paris")               │
                 * │    • locale            — locale (e.g., "en-US")                        │
                 * │    • updated_at        — last time profile was updated (Unix ts)       │
                 * │                                                                        │
                 * │  SPRING CONSTANT: OidcScopes.PROFILE = "profile"                      │
                 * └────────────────────────────────────────────────────────────────────────┘
                 *
                 * ┌────────────────────────────────────────────────────────────────────────┐
                 * │  3. email                                                              │
                 * ├────────────────────────────────────────────────────────────────────────┤
                 * │                                                                        │
                 * │  PURPOSE: Grants access to the user's email address and whether        │
                 * │           it has been verified.                                         │
                 * │                                                                        │
                 * │  CLAIMS UNLOCKED:                                                      │
                 * │    • email              — the user's email address                     │
                 * │    • email_verified     — boolean, true if the email has been verified │
                 * │                                                                        │
                 * │  SPRING CONSTANT: OidcScopes.EMAIL = "email"                          │
                 * │                                                                        │
                 * │  NOTE: This scope is NOT currently registered for our client.          │
                 * │        To add it:  .scope(OidcScopes.EMAIL)                           │
                 * └────────────────────────────────────────────────────────────────────────┘
                 *
                 * ┌────────────────────────────────────────────────────────────────────────┐
                 * │  4. address                                                            │
                 * ├────────────────────────────────────────────────────────────────────────┤
                 * │                                                                        │
                 * │  PURPOSE: Grants access to the user's physical mailing address.        │
                 * │                                                                        │
                 * │  CLAIMS UNLOCKED:                                                      │
                 * │    • address            — a JSON object containing:                    │
                 * │        ├─ formatted       — full mailing address as a single string    │
                 * │        ├─ street_address  — street, P.O. box, apartment, etc.          │
                 * │        ├─ locality        — city or town                               │
                 * │        ├─ region          — state, province, or region                 │
                 * │        ├─ postal_code     — zip or postal code                         │
                 * │        └─ country         — country name                               │
                 * │                                                                        │
                 * │  SPRING CONSTANT: OidcScopes.ADDRESS = "address"                      │
                 * │                                                                        │
                 * │  NOTE: Rarely used in modern apps. Most apps only need email +         │
                 * │        profile. If your app ships physical goods, this is useful.      │
                 * └────────────────────────────────────────────────────────────────────────┘
                 *
                 * ┌────────────────────────────────────────────────────────────────────────┐
                 * │  5. phone                                                              │
                 * ├────────────────────────────────────────────────────────────────────────┤
                 * │                                                                        │
                 * │  PURPOSE: Grants access to the user's phone number and verification   │
                 * │           status.                                                       │
                 * │                                                                        │
                 * │  CLAIMS UNLOCKED:                                                      │
                 * │    • phone_number          — the user's phone (e.g., "+1-555-555-5555")│
                 * │    • phone_number_verified — boolean, true if verified via SMS/call    │
                 * │                                                                        │
                 * │  SPRING CONSTANT: OidcScopes.PHONE = "phone"                          │
                 * │                                                                        │
                 * │  NOTE: Useful for apps that need 2FA or SMS notifications.             │
                 * └────────────────────────────────────────────────────────────────────────┘
                 *
                 * ── CUSTOM SCOPES ──
                 *
                 *   Beyond the 5 OIDC standard scopes, you can define your OWN scopes
                 *   for fine-grained API access control. Custom scopes are plain strings
                 *   — there's no special format required.
                 *
                 *   EXAMPLES:
                 *     .scope("read")             // read-only access to resources
                 *     .scope("write")            // write access to resources
                 *     .scope("admin")            // administrative operations
                 *     .scope("orders:read")      // read access to orders API
                 *     .scope("orders:write")     // write access to orders API
                 *     .scope("payments:charge")  // permission to charge payments
                 *
                 *   The Resource Server enforces these in its endpoint security:
                 *
                 *     @GetMapping("/api/orders")
                 *     @PreAuthorize("hasAuthority('SCOPE_orders:read')")
                 *     public List<Order> getOrders() { ... }
                 *
                 *   Note: Spring prefixes scope-based authorities with "SCOPE_"
                 *   automatically when using oauth2ResourceServer() JWT config.
                 *
                 * ── SCOPE NEGOTIATION FLOW ──
                 *
                 *   1. Client REQUESTS scopes:
                 *        /oauth2/authorize?scope=openid profile email
                 *
                 *   2. Server VALIDATES scopes:
                 *        Are all requested scopes registered for this client?
                 *        If the client requests "admin" but only has "openid profile"
                 *        registered → the server rejects the request.
                 *
                 *   3. User CONSENTS to scopes (on the consent screen):
                 *        The user sees:
                 *          ☑ Access your profile information (profile)
                 *          ☑ Access your email address (email)
                 *          ☐ Access your phone number (phone)  ← user unchecks this
                 *        Only consented scopes are included in the token.
                 *
                 *   4. Token CONTAINS the granted scopes:
                 *        { "scope": "openid profile email" }
                 *        (phone was denied by the user, so it's excluded)
                 *
                 * ── WHAT DOES A /userinfo RESPONSE LOOK LIKE? ──
                 *
                 *   When the client calls GET /userinfo with a valid access token
                 *   that includes the openid + profile + email scopes, the response
                 *   contains ALL claims associated with those scopes:
                 *
                 *     {
                 *       "sub": "java-rush",
                 *       "name": "Java Rush",
                 *       "given_name": "Java",
                 *       "family_name": "Rush",
                 *       "preferred_username": "java-rush",
                 *       "picture": "https://example.com/avatar.jpg",
                 *       "locale": "en-US",
                 *       "updated_at": 1717196400,
                 *       "email": "java@rush.dev",
                 *       "email_verified": true
                 *     }
                 *
                 *   To populate these claims in Spring Authorization Server, you
                 *   customize the OidcUserInfoMapper or add claims via a
                 *   OAuth2TokenCustomizer<JwtEncodingContext> bean.
                 *
                 * ── SCOPES REGISTERED FOR THIS CLIENT ──
                 *   Currently, this client has TWO scopes registered:
                 *     • openid  → enables OIDC + ID Token issuance
                 *     • profile → unlocks basic profile claims
                 */
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
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
     * BEAN 5 — OAuth2 Authorization Service (JDBC)
     * ─────────────────────────────────────────────────────────────────────────────────
     *
     * Stores OAuth2 authorizations (tokens, codes, etc.) in PostgreSQL.
     * Defined explicitly because the filter chain depends on it at construction time.
     *
     * BACKED BY: The 'oauth2_authorization' table in the 'public' schema.
     *
     * WHAT IT STORES:
     *   • Authorization codes (during the auth-code flow, before exchange)
     *   • Access tokens (JWT value, metadata, scopes, expiry)
     *   • Refresh tokens (opaque value, metadata, expiry)
     *   • OIDC ID tokens (JWT value, metadata, expiry)
     *   • Device codes (if device authorization grant is used)
     *
     * WHY JDBC?
     *   In-memory storage is lost on every restart — all issued tokens become
     *   invalid. JDBC persistence means tokens survive server restarts and can
     *   be shared across multiple instances of the authorization server.
     */
    @Bean
    public OAuth2AuthorizationService authorizationService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * ─────────────────────────────────────────────────────────────────────────────────
     * BEAN 6 — OAuth2 Authorization Consent Service (JDBC)
     * ─────────────────────────────────────────────────────────────────────────────────
     *
     * Stores user consent decisions (which scopes the user approved) in PostgreSQL.
     *
     * BACKED BY: The 'oauth2_authorization_consent' table in the 'public' schema.
     *
     * WHAT IT STORES:
     *   • One row per (registered_client_id, principal_name) pair
     *   • The 'authorities' column contains the granted scopes (e.g., "openid profile")
     *
     * WHY JDBC?
     *   With in-memory storage, users must re-consent on every server restart.
     *   JDBC persistence remembers consent across restarts — if a user already
     *   approved "openid profile" for a client, they won't be prompted again.
     */
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }
}
