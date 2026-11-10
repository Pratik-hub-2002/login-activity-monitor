-- Adds nullable email storage without changing or deleting existing users.
-- Safe to run repeatedly against MySQL 8.
SET @user_email_column_exists = (
    SELECT COUNT(*)
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'users'
      AND COLUMN_NAME = 'email_address'
);

SET @user_email_migration = IF(
    @user_email_column_exists = 0,
    'ALTER TABLE users ADD COLUMN email_address VARCHAR(254) NULL',
    'SELECT 1'
);

PREPARE user_email_statement FROM @user_email_migration;
EXECUTE user_email_statement;
DEALLOCATE PREPARE user_email_statement;
