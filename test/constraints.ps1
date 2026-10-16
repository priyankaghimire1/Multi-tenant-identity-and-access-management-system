# Database constraint tests, self-contained: the SQL is embedded below.
# Runs against the "app" database inside the postgres container, in one transaction
# that is rolled back, so it never leaves data behind.
#
# From the project root:   .\test\constraints.ps1
# Uses POSTGRES_USER from .env (default: postgres).
# Tests the invariants in gateway/prisma/migrations/20261009000000_m1_init/migration.sql

$user = "postgres"
if (Test-Path .env) {
  $line = Select-String -Path .env -Pattern '^POSTGRES_USER=(.+)$' | Select-Object -First 1
  if ($line) { $user = $line.Matches[0].Groups[1].Value.Trim() }
}

# Single-quoted here-string: PowerShell does not expand $ inside, so the SQL is sent unchanged.
# Keep the closing '@ at the start of its line.
$sql = @'
-- Executable tests for the database invariants in
-- gateway/prisma/migrations/20261009000000_m1_init/migration.sql
--
-- Everything runs inside one transaction that is rolled back, so it never leaves data behind.
-- Run:  .\test\constraints.ps1
-- A failing check raises an exception, so psql exits non-zero.

BEGIN;

CREATE FUNCTION pg_temp.expect_fail(test_name text, stmt text, expected_state text) RETURNS void AS $$
BEGIN
  BEGIN
    EXECUTE stmt;
  EXCEPTION WHEN OTHERS THEN
    IF SQLSTATE = expected_state THEN
      RAISE NOTICE 'PASS  %', test_name;
      RETURN;
    END IF;
    RAISE EXCEPTION 'FAIL  % (expected SQLSTATE %, got % : %)', test_name, expected_state, SQLSTATE, SQLERRM;
  END;
  RAISE EXCEPTION 'FAIL  % (statement succeeded but must be rejected)', test_name;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION pg_temp.expect_ok(test_name text, stmt text) RETURNS void AS $$
BEGIN
  EXECUTE stmt;
  RAISE NOTICE 'PASS  %', test_name;
EXCEPTION WHEN OTHERS THEN
  RAISE EXCEPTION 'FAIL  % (should succeed, got % : %)', test_name, SQLSTATE, SQLERRM;
END;
$$ LANGUAGE plpgsql;

-- Fixtures: two users, one organization with a single OWNER
INSERT INTO users (id, email) VALUES
  ('00000000-0000-4000-8000-000000000001', 'u1@test.local'),
  ('00000000-0000-4000-8000-000000000002', 'u2@test.local'),
  ('00000000-0000-4000-8000-000000000003', 'u3@test.local');
INSERT INTO organizations (id, slug, name) VALUES
  ('10000000-0000-4000-8000-000000000001', 'org-one', 'Org One');
INSERT INTO memberships (id, org_id, user_id, role) VALUES
  ('20000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000001',
   '00000000-0000-4000-8000-000000000001', 'OWNER');

-- Organizations -----------------------------------------------------------
SELECT pg_temp.expect_fail('slug with uppercase is rejected',
  $q$INSERT INTO organizations (slug, name) VALUES ('Bad', 'x')$q$, '23514');
SELECT pg_temp.expect_fail('slug starting with a hyphen is rejected',
  $q$INSERT INTO organizations (slug, name) VALUES ('-bad', 'x')$q$, '23514');
SELECT pg_temp.expect_fail('one-character slug is rejected',
  $q$INSERT INTO organizations (slug, name) VALUES ('a', 'x')$q$, '23514');
SELECT pg_temp.expect_fail('blank organization name is rejected',
  $q$INSERT INTO organizations (slug, name) VALUES ('blank-name', '   ')$q$, '23514');
SELECT pg_temp.expect_fail('duplicate slug is rejected',
  $q$INSERT INTO organizations (slug, name) VALUES ('org-one', 'Dup')$q$, '23505');

-- Memberships -------------------------------------------------------------
SELECT pg_temp.expect_fail('same user twice in one organization is rejected',
  $q$INSERT INTO memberships (org_id, user_id, role) VALUES
     ('10000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000001', 'MEMBER')$q$, '23505');
SELECT pg_temp.expect_fail('unknown role is rejected',
  $q$INSERT INTO memberships (org_id, user_id, role) VALUES
     ('10000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000002', 'SUPERUSER')$q$, '22P02');
SELECT pg_temp.expect_fail('membership in a non-existent organization is rejected',
  $q$INSERT INTO memberships (org_id, user_id) VALUES
     ('99999999-9999-4999-8999-999999999999', '00000000-0000-4000-8000-000000000002')$q$, '23503');
SELECT pg_temp.expect_fail('membership for a non-existent user is rejected',
  $q$INSERT INTO memberships (org_id, user_id) VALUES
     ('10000000-0000-4000-8000-000000000001', '99999999-9999-4999-8999-999999999999')$q$, '23503');
SELECT pg_temp.expect_fail('organization with members cannot be deleted',
  $q$DELETE FROM organizations WHERE id = '10000000-0000-4000-8000-000000000001'$q$, '23503');

-- A user can belong to several organizations
SELECT pg_temp.expect_ok('same user can join a second organization',
  $q$WITH o AS (INSERT INTO organizations (slug, name) VALUES ('org-two', 'Org Two') RETURNING id)
     INSERT INTO memberships (org_id, user_id, role)
     SELECT id, '00000000-0000-4000-8000-000000000001', 'MEMBER' FROM o$q$);

-- Last-owner invariant ------------------------------------------------------
SELECT pg_temp.expect_fail('cannot demote the last OWNER',
  $q$UPDATE memberships SET role = 'ADMIN' WHERE id = '20000000-0000-4000-8000-000000000001'$q$, '23514');
SELECT pg_temp.expect_fail('cannot suspend the last OWNER',
  $q$UPDATE memberships SET status = 'SUSPENDED' WHERE id = '20000000-0000-4000-8000-000000000001'$q$, '23514');
SELECT pg_temp.expect_fail('cannot delete the last OWNER',
  $q$DELETE FROM memberships WHERE id = '20000000-0000-4000-8000-000000000001'$q$, '23514');
SELECT pg_temp.expect_fail('cannot delete a user who is the last OWNER of an organization',
  $q$DELETE FROM users WHERE id = '00000000-0000-4000-8000-000000000001'$q$, '23514');

SELECT pg_temp.expect_ok('a second OWNER can be added',
  $q$INSERT INTO memberships (org_id, user_id, role) VALUES
     ('10000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000002', 'OWNER')$q$);
SELECT pg_temp.expect_ok('with two OWNERs, one can be demoted',
  $q$UPDATE memberships SET role = 'ADMIN' WHERE id = '20000000-0000-4000-8000-000000000001'$q$);
SELECT pg_temp.expect_fail('the remaining OWNER is now protected',
  $q$UPDATE memberships SET role = 'MEMBER'
     WHERE org_id = '10000000-0000-4000-8000-000000000001' AND role = 'OWNER'$q$, '23514');

-- Device sessions -------------------------------------------------------------
INSERT INTO device_sessions (keycloak_sid, user_id) VALUES
  ('sid-1', '00000000-0000-4000-8000-000000000001');
SELECT pg_temp.expect_fail('duplicate Keycloak session id is rejected',
  $q$INSERT INTO device_sessions (keycloak_sid, user_id) VALUES ('sid-1', '00000000-0000-4000-8000-000000000002')$q$, '23505');
SELECT pg_temp.expect_fail('revocation before creation is rejected',
  $q$UPDATE device_sessions SET revoked_at = created_at - interval '1 day' WHERE keycloak_sid = 'sid-1'$q$, '23514');
SELECT pg_temp.expect_fail('session for a non-existent user is rejected',
  $q$INSERT INTO device_sessions (keycloak_sid, user_id) VALUES ('sid-2', '99999999-9999-4999-8999-999999999999')$q$, '23503');
SELECT pg_temp.expect_ok('a session can be revoked',
  $q$UPDATE device_sessions SET revoked_at = now() + interval '1 second' WHERE keycloak_sid = 'sid-1'$q$);

DO $$ BEGIN RAISE NOTICE 'ALL CONSTRAINT TESTS PASSED'; END $$;

ROLLBACK;
'@

$sql | docker compose exec -T postgres psql -U $user -d app -v ON_ERROR_STOP=1 2>&1 |
  ForEach-Object {
    $t = "$_"
    if ($t -match "PASS")           { Write-Host $t -ForegroundColor Green }
    elseif ($t -match "FAIL|ERROR") { Write-Host $t -ForegroundColor Red }
    else                            { Write-Host $t }
  }

if ($LASTEXITCODE -ne 0) { Write-Host "constraint tests FAILED" -ForegroundColor Red; exit 1 }