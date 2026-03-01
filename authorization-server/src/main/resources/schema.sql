/*
 * =====================================================================================
 * Spring Authorization Server — JDBC Schema for PostgreSQL
 * =====================================================================================
 *
 * These tables are required by the JDBC-backed implementations:
 *   • JdbcOAuth2AuthorizationService       → oauth2_authorization
 *   • JdbcOAuth2AuthorizationConsentService → oauth2_authorization_consent
 *
 * NOTE: PostgreSQL does NOT support the 'blob' type. All blob columns from the
 *       default H2/MySQL schema are replaced with 'text' for PostgreSQL.
 *
 * SOURCE: Official Spring Authorization Server DDL (1.1.x branch)
 *         https://github.com/spring-projects/spring-authorization-server
 */

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE 1 — oauth2_authorization
-- ─────────────────────────────────────────────────────────────────────────────
-- Stores every OAuth2 authorization: authorization codes, access tokens,
-- refresh tokens, OIDC ID tokens, and device codes. Each row represents
-- one authorization lifecycle (from code issuance through token exchange).
CREATE TABLE IF NOT EXISTS oauth2_authorization (
    id                            varchar(100)  NOT NULL,
    registered_client_id          varchar(100)  NOT NULL,
    principal_name                varchar(200)  NOT NULL,
    authorization_grant_type      varchar(100)  NOT NULL,
    authorized_scopes             varchar(1000) DEFAULT NULL,
    attributes                    text          DEFAULT NULL,
    state                         varchar(500)  DEFAULT NULL,
    authorization_code_value      text          DEFAULT NULL,
    authorization_code_issued_at  timestamp     DEFAULT NULL,
    authorization_code_expires_at timestamp     DEFAULT NULL,
    authorization_code_metadata   text          DEFAULT NULL,
    access_token_value            text          DEFAULT NULL,
    access_token_issued_at        timestamp     DEFAULT NULL,
    access_token_expires_at       timestamp     DEFAULT NULL,
    access_token_metadata         text          DEFAULT NULL,
    access_token_type             varchar(100)  DEFAULT NULL,
    access_token_scopes           varchar(1000) DEFAULT NULL,
    oidc_id_token_value           text          DEFAULT NULL,
    oidc_id_token_issued_at       timestamp     DEFAULT NULL,
    oidc_id_token_expires_at      timestamp     DEFAULT NULL,
    oidc_id_token_metadata        text          DEFAULT NULL,
    refresh_token_value           text          DEFAULT NULL,
    refresh_token_issued_at       timestamp     DEFAULT NULL,
    refresh_token_expires_at      timestamp     DEFAULT NULL,
    refresh_token_metadata        text          DEFAULT NULL,
    user_code_value               text          DEFAULT NULL,
    user_code_issued_at           timestamp     DEFAULT NULL,
    user_code_expires_at          timestamp     DEFAULT NULL,
    user_code_metadata            text          DEFAULT NULL,
    device_code_value             text          DEFAULT NULL,
    device_code_issued_at         timestamp     DEFAULT NULL,
    device_code_expires_at        timestamp     DEFAULT NULL,
    device_code_metadata          text          DEFAULT NULL,
    PRIMARY KEY (id)
);

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE 2 — oauth2_authorization_consent
-- ─────────────────────────────────────────────────────────────────────────────
-- Stores user consent decisions: which scopes the user approved for each client.
-- Composite PK on (registered_client_id, principal_name) means one consent
-- record per user-client pair.
CREATE TABLE IF NOT EXISTS oauth2_authorization_consent (
    registered_client_id varchar(100)  NOT NULL,
    principal_name       varchar(200)  NOT NULL,
    authorities          varchar(1000) NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name)
);
