package dev.javarush.authorizationserver.grant.password;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * =====================================================================================
 * RESOURCE OWNER PASSWORD AUTHENTICATION CONVERTER
 * =====================================================================================
 *
 * Converts an incoming HTTP request at the /oauth2/token endpoint into a
 * {@link ResourceOwnerPasswordAuthenticationToken} when the grant_type is "password".
 *
 * ── What this does in the OAuth 2.0 flow ──
 *   The client sends a POST to /oauth2/token with:
 *     grant_type=password
 *     username=<user>
 *     password=<pass>
 *     scope=<optional scopes>    (space-separated)
 *     + client authentication via Basic auth header
 *
 *   This converter:
 *     1. Checks if grant_type == "password" (returns null otherwise, letting other converters try)
 *     2. Extracts username, password, and scopes from the request
 *     3. Gets the already-authenticated client principal from the SecurityContext
 *     4. Creates and returns a ResourceOwnerPasswordAuthenticationToken
 */
public class ResourceOwnerPasswordAuthenticationConverter implements AuthenticationConverter {

    @Override
    public Authentication convert(HttpServletRequest request) {
        // Only handle the "password" grant type — return null for others
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!"password".equals(grantType)) {
            return null;
        }

        // The client has already been authenticated by the framework's client auth filter
        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        // Extract and validate username
        String username = request.getParameter(OAuth2ParameterNames.USERNAME);
        if (!StringUtils.hasText(username)) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "username is required", null));
        }

        // Extract and validate password
        String password = request.getParameter(OAuth2ParameterNames.PASSWORD);
        if (!StringUtils.hasText(password)) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "password is required", null));
        }

        // Parse optional scopes (space-separated string → Set)
        String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
        Set<String> scopes = null;
        if (StringUtils.hasText(scope)) {
            scopes = new HashSet<>();
            for (String s : scope.split(" ")) {
                if (StringUtils.hasText(s)) {
                    scopes.add(s);
                }
            }
        }

        // Collect any additional parameters (for extensibility)
        Map<String, Object> additionalParameters = new HashMap<>();
        request.getParameterMap().forEach((key, values) -> {
            if (!OAuth2ParameterNames.GRANT_TYPE.equals(key)
                    && !OAuth2ParameterNames.USERNAME.equals(key)
                    && !OAuth2ParameterNames.PASSWORD.equals(key)
                    && !OAuth2ParameterNames.SCOPE.equals(key)) {
                additionalParameters.put(key, values[0]);
            }
        });

        return new ResourceOwnerPasswordAuthenticationToken(
                clientPrincipal, username, password, scopes, additionalParameters);
    }
}
