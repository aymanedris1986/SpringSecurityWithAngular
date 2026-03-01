/*
 * =====================================================================================
 * Spring Security — Seed Data for JdbcUserDetailsManager
 * =====================================================================================
 *
 * This file runs AFTER schema.sql on every application startup (controlled by
 * spring.sql.init.mode=always in application.yaml).
 *
 * EXECUTION ORDER:
 *   1. DataSource is created (connection pool to PostgreSQL)
 *   2. schema.sql → CREATE TABLE IF NOT EXISTS users, authorities, ...
 *   3. data.sql   → INSERT demo users (this file)
 *   4. Spring beans are instantiated (JdbcUserDetailsManager, etc.)
 *
 * The ON CONFLICT DO NOTHING clause (PostgreSQL-specific) ensures this script
 * is idempotent — it won't fail or duplicate rows on subsequent startups.
 *
 * IN PRODUCTION:
 *   Remove this file and manage user creation via a registration API
 *   or an admin panel. Use spring.sql.init.mode=never in production.
 */

-- ── Demo User ────────────────────────────────────────────────────────────────
-- Username:    java-rush
-- Password:    pass  (plain text — only because NoOpPasswordEncoder is used)
-- Authority:   read
INSERT INTO users (username, password, enabled)
VALUES ('java-rush', 'pass', true)
ON CONFLICT (username) DO NOTHING;

INSERT INTO authorities (username, authority)
VALUES ('java-rush', 'read')
ON CONFLICT DO NOTHING;
