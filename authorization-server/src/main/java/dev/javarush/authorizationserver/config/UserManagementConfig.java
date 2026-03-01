package dev.javarush.authorizationserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
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
     */
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("java-rush")
                .password("pass")
                .authorities("read")
                .build();

        return new InMemoryUserDetailsManager(user);
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
