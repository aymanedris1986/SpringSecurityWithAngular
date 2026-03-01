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
 *
 * ── HOW THIS SCRIPT RUNS ON APPLICATION STARTUP ──
 *
 * This schema.sql file is automatically executed by Spring Boot during application
 * startup through the following mechanism:
 *
 *   1. SPRING BOOT AUTO-CONFIGURATION:
 *      Spring Boot's DataSourceInitializer automatically looks for schema.sql
 *      in src/main/resources/ and executes it against the configured DataSource.
 *
 *   2. EXECUTION ORDER:
 *      • schema.sql runs FIRST (creates tables, indexes, constraints)
 *      • data.sql runs SECOND (inserts initial data, if present)
 *
 *   3. CONFIGURATION PROPERTIES:
 *      The behavior is controlled by these application.yml properties:
 *        spring.sql.init.mode: always          # Run scripts on every startup
 *        spring.sql.init.schema-locations:     # Override default schema.sql location
 *        spring.sql.init.data-locations:       # Override default data.sql location
 *        spring.sql.init.continue-on-error:    # Continue if script fails
 *
 *   4. DATABASE INITIALIZATION FLOW:
 *      Application Startup → DataSource Bean Creation → Schema Initialization
 *      → JdbcTemplate Bean Creation → Authorization Server Beans → Ready
 *
 *   5. WHY THIS MATTERS FOR OAUTH2:
 *      The JdbcOAuth2AuthorizationService and JdbcOAuth2AuthorizationConsentService
 *      beans (configured in AuthorizationServerConfig) depend on these tables
 *      existing. If schema.sql fails or is skipped, the authorization server
 *      will fail to start with table-not-found errors.
 *
 *   6. PRODUCTION CONSIDERATIONS:
 *      • Use spring.sql.init.mode: never in production
 *      • Manage schema with Flyway or Liquibase instead
 *      • This auto-execution is primarily for development/testing
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
