-- Failed-login lockout. A user is locked for a fixed period after enough
-- consecutive failures; a second lockout is permanent until an admin unlocks.
ALTER TABLE users ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN lockout_count      INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN locked_until       TEXT;
ALTER TABLE users ADD COLUMN is_locked          INTEGER NOT NULL DEFAULT 0;
