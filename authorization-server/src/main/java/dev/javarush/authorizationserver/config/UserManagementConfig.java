package dev.javarush.authorizationserver.config;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * =====================================================================================
 * USER MANAGEMENT CONFIGURATION
 * =====================================================================================
 *
 * This class handles the RESOURCE OWNER (end-user) side of the OAuth 2.0 flow.
 * While AuthorizationServerConfig configures the OAuth 2.0 protocol endpoints and
 * client registration, THIS config handles:
 *   1. How the end-user AUTHENTICATES (login form)
 *   2. Where user credentials are stored and validated
 *   3. How passwords are encoded/verified
 *
 * ── Where This Fits in the OAuth 2.0 Authorization Code Flow ──
 *
 *   Step 1: Client redirects user to /oauth2/authorize
 *           → AuthorizationServerConfig's filter chain handles this endpoint
 *
 *   Step 2: User is NOT authenticated yet → redirected to /login
 *           → THIS config's filter chain kicks in (serves the login form)
 *
 *   Step 3: User submits credentials (username + password)
 *           → THIS config's UserDetailsService validates the credentials
 *           → THIS config's PasswordEncoder verifies the password
 *
 *   Step 4: Authentication succeeds → user is redirected BACK to /oauth2/authorize
 *           → AuthorizationServerConfig takes over again to issue the auth code
 *
 *   In short: AuthorizationServerConfig handles the OAuth 2.0 PROTOCOL,
 *             UserManagementConfig handles the USER AUTHENTICATION that the protocol requires.
 *
 * ── OAuth 2.0 Principle: Resource Owner Authentication ──
 *   The OAuth 2.0 spec (RFC 6749 §3.1) requires the authorization endpoint to first
 *   authenticate the resource owner. HOW authentication happens is NOT defined by
 *   OAuth 2.0 — it's left up to the authorization server. Here we use a simple
 *   form-based login, but it could be SSO, MFA, biometrics, etc.
 *
 * ── Bean Ordering & Interaction ──
 *   This config defines 3 beans:
 *     [1] userManagementSecurityFilterChain — HTTP security for user-facing pages
 *     [2] userDetailsService               — Where user accounts are stored
 *     [3] passwordEncoder                  — How passwords are verified
 */
@Configuration
public class UserManagementConfig {

    /**
     * ─────────────────────────────────────────────────────────────────────────────────
     * BEAN 1 — User Management Security Filter Chain
     * ─────────────────────────────────────────────────────────────────────────────────
     *
     * FLOW ORDER: ★ This is the SECOND filter chain evaluated (@Order(2) effectively).
     *
     * PURPOSE:
     *   This filter chain secures ALL non-OAuth2 requests — essentially the
     *   user-facing parts of the authorization server, most importantly the LOGIN PAGE.
     *
     * HOW IT WORKS WITH AuthorizationServerConfig:
     *   Spring Security evaluates filter chains in @Order sequence:
     *     1. @Order(1) — AuthorizationServerConfig's chain checks if the request
     *        matches an OAuth 2.0 endpoint (e.g., /oauth2/token, /oauth2/authorize).
     *        If YES → that chain handles it. If NO → falls through.
     *     2. @Order(2) — THIS chain catches everything else (including /login).
     *        It requires authentication for all requests and provides a form login.
     *
     * WHY .authorizeHttpRequests(anyRequest().authenticated())?
     *   Ensures that EVERY request hitting this filter chain requires the user to be
     *   authenticated. If the user isn't logged in, Spring Security will trigger the
     *   form login flow.
     *
     * WHY .formLogin(Customizer.withDefaults())?
     *   Enables Spring Security's built-in form-based login mechanism:
     *     • Auto-generates a login page at /login (GET)
     *     • Handles login form submission at /login (POST)
     *     • Manages session creation upon successful authentication
     *     • Provides default logout support
     *
     *   This is the login page that users see when the AuthorizationServerConfig
     *   redirects unauthenticated users (via LoginUrlAuthenticationEntryPoint("/login")).
     *
     * OAUTH 2.0 PRINCIPLE:
     *   The authorization server must authenticate the resource owner before granting
     *   authorization. Form login is the mechanism used here to collect and verify
     *   the user's credentials. Once authenticated, the user's session is established,
     *   and control returns to the OAuth 2.0 authorization endpoint.
     *
     * NOTE on @Order(1): There is a conflict — both this chain and the authorization
     *   server chain use @Order(1). In practice, Spring Authorization Server's chain
     *   has more specific request matchers (only OAuth 2.0 endpoints), so it takes
     *   priority for those URLs. This chain, with anyRequest(), acts as the catch-all.
     *   However, it is BEST PRACTICE to use @Order(2) here to make the intent explicit.
     */
    @Bean
    @Order(2)
    public SecurityFilterChain userManagementSecurityFilterChain(
            HttpSecurity http
    ) throws Exception {
        http.authorizeHttpRequests(
                authz -> authz
                        .anyRequest().authenticated()
        )
                .formLogin(Customizer.withDefaults());
        return http.build();
    }

    /**
     * ─────────────────────────────────────────────────────────────────────────────────
     * BEAN 2 — User Details Service
     * ─────────────────────────────────────────────────────────────────────────────────
     *
     * FLOW ORDER: ★ Invoked during STEP 3 — when the user submits the login form.
     *
     * PURPOSE:
     *   Defines WHERE and HOW user accounts are stored and retrieved. Spring Security
     *   calls loadUserByUsername(username) when the user submits the login form. The
     *   returned UserDetails object contains:
     *     • Username         — the identity of the user
     *     • Password         — the stored (encoded) password for comparison
     *     • Authorities      — granted permissions (roles/privileges)
     *     • Account status   — enabled, locked, expired, etc.
     *
     * OAUTH 2.0 PRINCIPLE — Resource Owner Credentials:
     *   The resource owner (user) proves their identity by providing credentials.
     *   The UserDetailsService is the bridge between the login form and the user
     *   store. In this demo, we use InMemoryUserDetailsManager with a single
     *   hardcoded user.
     *
     * IN PRODUCTION:
     *   Replace InMemoryUserDetailsManager with a JdbcUserDetailsManager or a
     *   custom implementation that queries your database. For example:
     *
     *     @Bean
     *     public UserDetailsService userDetailsService(UserRepository repo) {
     *         return username -> repo.findByUsername(username)
     *             .map(user -> User.withUsername(user.getUsername())
     *                 .password(user.getPassword())
     *                 .authorities(user.getAuthorities())
     *                 .build())
     *             .orElseThrow(() -> new UsernameNotFoundException(username));
     *     }
     *
     * DEMO USER:
     *   Username:    java-rush
     *   Password:    pass
     *   Authorities: read (a simple granted authority)
     *
     * ── PASSWORDLESS LOGIN ──────────────────────────────────────────────────────
     *
     *   Passwordless authentication removes the password entirely. The user proves
     *   their identity through an alternative factor (something they HAVE or ARE)
     *   instead of something they KNOW. Below are the three main strategies and
     *   how each integrates with Spring Security's architecture.
     *
     * ─── APPROACH 1: OTP / Magic Link (Email or SMS) ────────────────────────────
     *
     *   CONCEPT:
     *     The user provides their email or phone number. The server generates a
     *     one-time password (OTP) or a signed magic link and delivers it out-of-band
     *     (email / SMS). The user then submits the OTP or clicks the magic link to
     *     complete authentication.
     *
     *   HOW IT WORKS WITH SPRING SECURITY:
     *
     *     1. Custom Authentication Filter (extends OncePerRequestFilter or
     *        AbstractAuthenticationProcessingFilter):
     *        - Intercepts POST /login/otp-request → generates & sends OTP
     *        - Intercepts POST /login/otp-verify  → validates OTP & authenticates
     *
     *     2. Custom AuthenticationToken:
     *
     *          public class OtpAuthenticationToken
     *                  extends AbstractAuthenticationToken {
     *
     *              private final String identifier;  // email or phone
     *              private final String otp;
     *
     *              // Pre-authentication constructor (unauthenticated)
     *              public OtpAuthenticationToken(String identifier, String otp) {
     *                  super(Collections.emptyList());
     *                  this.identifier = identifier;
     *                  this.otp = otp;
     *                  setAuthenticated(false);
     *              }
     *
     *              // Post-authentication constructor (authenticated)
     *              public OtpAuthenticationToken(String identifier,
     *                      Collection<? extends GrantedAuthority> authorities) {
     *                  super(authorities);
     *                  this.identifier = identifier;
     *                  this.otp = null;
     *                  setAuthenticated(true);
     *              }
     *          }
     *
     *     3. Custom AuthenticationProvider:
     *
     *          @Component
     *          public class OtpAuthenticationProvider
     *                  implements AuthenticationProvider {
     *
     *              private final OtpService otpService;
     *              private final UserDetailsService userDetailsService;
     *
     *              @Override
     *              public Authentication authenticate(Authentication auth) {
     *                  OtpAuthenticationToken token = (OtpAuthenticationToken) auth;
     *                  if (!otpService.verify(token.getIdentifier(), token.getOtp())) {
     *                      throw new BadCredentialsException("Invalid OTP");
     *                  }
     *                  UserDetails user = userDetailsService
     *                          .loadUserByUsername(token.getIdentifier());
     *                  return new OtpAuthenticationToken(
     *                          user.getUsername(), user.getAuthorities());
     *              }
     *
     *              @Override
     *              public boolean supports(Class<?> authType) {
     *                  return OtpAuthenticationToken.class.isAssignableFrom(authType);
     *              }
     *          }
     *
     *     4. OTP Storage — the OtpService needs a short-lived store:
     *        - Redis (TTL-based expiry, recommended for distributed systems)
     *        - Database table (e.g., otp_challenges with columns:
     *            id, identifier, otp_hash, expires_at, verified)
     *        - In-memory cache (ConcurrentHashMap + ScheduledExecutor, dev only)
     *
     *     5. Wire into the filter chain (in this config class):
     *
     *          http
     *              .addFilterBefore(otpFilter,
     *                      UsernamePasswordAuthenticationFilter.class)
     *              .authenticationProvider(otpAuthenticationProvider);
     *
     *   MAGIC LINK VARIANT:
     *     Instead of a numeric OTP, generate a signed JWT or opaque token embedded
     *     in a URL (e.g., /login/verify?token=xyz). The filter intercepts GET
     *     /login/verify, validates the token, and creates an authenticated session.
     *     Use short expiry (5–10 min) and single-use semantics (mark as consumed).
     *
     * ─── APPROACH 2: WebAuthn / Passkeys (FIDO2) ───────────────────────────────
     *
     *   CONCEPT:
     *     Uses public-key cryptography tied to the user's device or platform
     *     authenticator (fingerprint, face, security key). No shared secret is ever
     *     transmitted — the private key never leaves the user's device.
     *
     *   SPRING SECURITY 6.4+ SUPPORT:
     *     Spring Security 6.4 introduced first-class WebAuthn/Passkey support:
     *
     *          http
     *              .webAuthn(webAuthn -> webAuthn
     *                  .rpName("My Application")
     *                  .rpId("example.com")
     *                  .allowedOrigins("https://example.com")
     *              );
     *
     *     This auto-configures:
     *       • POST /webauthn/register/options  — begin registration ceremony
     *       • POST /webauthn/register           — complete registration
     *       • Registration of WebAuthnAuthenticationProvider
     *       • A default PublicKeyCredentialUserEntityRepository
     *
     *   FOR OLDER SPRING SECURITY VERSIONS:
     *     Use the java-webauthn-server library (by Yubico) and build custom:
     *       • RegistrationController — handles attestation ceremony
     *       • AuthenticationFilter   — handles assertion ceremony
     *       • CredentialRepository   — stores public keys per user
     *
     *   HOW IT TIES INTO OAUTH 2.0:
     *     The WebAuthn flow authenticates the user and establishes a session. Once
     *     the session exists, the OAuth 2.0 authorization endpoint (/oauth2/authorize)
     *     sees the user as authenticated and proceeds with the code/token grant.
     *     WebAuthn replaces the formLogin() — the authorization flow is unaffected.
     *
     * ─── APPROACH 3: OAuth 2.0 Social / Federated Login ────────────────────────
     *
     *   CONCEPT:
     *     Delegate authentication to an external identity provider (Google, GitHub,
     *     Apple, etc.). The user authenticates with the external IdP and your server
     *     receives a verified identity (ID token / user-info). No password is stored
     *     locally at all.
     *
     *   SPRING SECURITY CONFIGURATION:
     *
     *          http
     *              .oauth2Login(oauth2 -> oauth2
     *                  .userInfoEndpoint(info -> info
     *                      .userService(customOAuth2UserService)
     *                  )
     *              );
     *
     *     Combined with application.yml:
     *
     *          spring.security.oauth2.client.registration.google:
     *            client-id: ${GOOGLE_CLIENT_ID}
     *            client-secret: ${GOOGLE_CLIENT_SECRET}
     *            scope: openid, profile, email
     *
     *   USER PROVISIONING:
     *     On first login, create (or link) a local user account from the ID token
     *     claims. The customOAuth2UserService maps the external identity to your
     *     internal UserDetails, effectively making the UserDetailsService bean
     *     unnecessary for social-only users.
     *
     * ─── INTEGRATING WITH THIS AUTHORIZATION SERVER ─────────────────────────────
     *
     *   KEY INSIGHT: Passwordless flows only change HOW the user authenticates in
     *   STEP 2–3 of the OAuth 2.0 Authorization Code flow. The rest of the flow
     *   (authorization code issuance, token exchange, client authentication)
     *   remains completely unchanged.
     *
     *   FILTER CHAIN IMPACT:
     *     Replace or augment .formLogin() in userManagementSecurityFilterChain():
     *
     *       // Passwordless with OTP — keep formLogin for fallback, add OTP filter
     *       http
     *           .addFilterBefore(otpFilter, UsernamePasswordAuthenticationFilter.class)
     *           .formLogin(Customizer.withDefaults());  // optional fallback
     *
     *       // Passwordless with Passkeys — replace formLogin entirely
     *       http
     *           .webAuthn(webAuthn -> webAuthn.rpName("My App").rpId("example.com"))
     *           .formLogin(Customizer.withDefaults());  // fallback for non-WebAuthn browsers
     *
     *       // Passwordless with Social Login
     *       http
     *           .oauth2Login(Customizer.withDefaults());  // replaces formLogin
     *
     *   UserDetailsService IMPACT:
     *     - OTP: Still needed — loadUserByUsername(email/phone) fetches the user.
     *     - Passkeys: Still needed — WebAuthn maps credentials to a user identity.
     *     - Social Login: May be replaced by a custom OAuth2UserService, but a
     *       UserDetailsService is still useful if you need to enrich the user with
     *       local authorities or support mixed login methods.
     *
     *   PasswordEncoder IMPACT:
     *     - OTP: NOT needed for user auth (OTP is verified differently), but keep
     *       it if the same server also handles OAuth2 client_secret verification.
     *     - Passkeys: NOT needed — no shared secret exists.
     *     - Social Login: NOT needed — authentication is delegated externally.
     */
    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        // ── JdbcUserDetailsManager ──────────────────────────────────────────────
        // JdbcUserDetailsManager is Spring Security's JDBC-backed implementation
        // of both UserDetailsService (read) and UserDetailsManager (CRUD).
        //
        // HOW IT WORKS:
        //   It delegates all user-related operations to SQL queries against the
        //   standard 'users' and 'authorities' tables. The DataSource is injected
        //   automatically from the Spring Boot auto-configuration (configured in
        //   application.yaml with the PostgreSQL connection details).
        //
        // DEFAULT QUERIES (used internally by JdbcUserDetailsManager):
        //   • loadUserByUsername: SELECT username, password, enabled
        //                        FROM users WHERE username = ?
        //   • findAuthorities:   SELECT username, authority
        //                        FROM authorities WHERE username = ?
        //   • createUser:        INSERT INTO users (username, password, enabled)
        //                        VALUES (?, ?, ?)
        //   • createAuthority:   INSERT INTO authorities (username, authority)
        //                        VALUES (?, ?)
        //
        // CUSTOM QUERIES (optional — override if your tables have different names):
        //   manager.setUsersByUsernameQuery(
        //       "SELECT username, password, enabled FROM my_users WHERE username = ?");
        //   manager.setAuthoritiesByUsernameQuery(
        //       "SELECT username, authority FROM my_authorities WHERE username = ?");
        //
        // KEY DIFFERENCE FROM InMemoryUserDetailsManager:
        //   InMemory stores users in a HashMap — lost on restart, no persistence.
        //   JDBC stores users in the database — survives restarts, shared across
        //   instances, auditable, and manageable via SQL.
        // ────────────────────────────────────────────────────────────────────────
        //
        // ⚠️ IMPORTANT — Do NOT call manager.userExists() or manager.createUser()
        //   here! This bean is constructed BEFORE Spring Boot's schema.sql runs,
        //   so the 'users' table does not exist yet during bean creation.
        //   Seed demo users via data.sql instead (see src/main/resources/data.sql).
        // ────────────────────────────────────────────────────────────────────────

        return new JdbcUserDetailsManager(dataSource);
    }

    /**
     * ─────────────────────────────────────────────────────────────────────────────────
     * BEAN 3 — Password Encoder
     * ─────────────────────────────────────────────────────────────────────────────────
     *
     * FLOW ORDER: ★ Invoked during STEP 3 — right after UserDetailsService returns
     *               the UserDetails. Spring Security uses the PasswordEncoder to
     *               compare the submitted raw password against the stored password.
     *
     * PURPOSE:
     *   Defines HOW passwords are encoded (for storage) and matched (for verification).
     *   The flow is:
     *     1. User types "pass" in the login form
     *     2. UserDetailsService returns UserDetails with stored password "pass"
     *     3. PasswordEncoder.matches("pass", "pass") → true → authentication succeeds
     *
     * ⚠️ WARNING — NoOpPasswordEncoder:
     *   NoOpPasswordEncoder performs NO encoding — passwords are stored and compared
     *   as plain text. This is ONLY acceptable for development and demos.
     *   It is DEPRECATED and will log warnings at startup.
     *
     * IN PRODUCTION — Use BCryptPasswordEncoder:
     *   BCrypt is the industry standard for password hashing. It includes:
     *     • Automatic salting (each hash is unique even for identical passwords)
     *     • Configurable work factor (cost parameter to slow down brute-force attacks)
     *     • One-way hashing (passwords cannot be reversed)
     *
     *   Replace with:
     *     @Bean
     *     public PasswordEncoder passwordEncoder() {
     *         return new BCryptPasswordEncoder();
     *     }
     *
     *   And encode passwords during user registration:
     *     passwordEncoder.encode("rawPassword")
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}
