-- Reviewed schema alignment for the PDF database contract.
-- Do not run until backed up and reviewed against the live schema.
-- This script never drops, deletes, truncates, or renumbers records.

-- Add timestamp when missing; SELECT 1 is a safe prepared no-op.
SET @add_login_timestamp := IF(
    EXISTS (
        SELECT 1 FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'login_attempts'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'login_attempts'
          AND COLUMN_NAME = 'timestamp'
    ),
    'ALTER TABLE login_attempts ADD COLUMN `timestamp` DATETIME NULL',
    'SELECT 1'
);
PREPARE add_login_timestamp_stmt FROM @add_login_timestamp;
EXECUTE add_login_timestamp_stmt;
DEALLOCATE PREPARE add_login_timestamp_stmt;

-- Copy legacy values only into null targets. If both columns contain different
-- non-null values, both are retained; manual reconciliation is required.
SET @copy_login_timestamp := IF(
    EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'login_attempts'
          AND COLUMN_NAME = 'attempt_time'
    ) AND EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'login_attempts'
          AND COLUMN_NAME = 'timestamp'
    ),
    'UPDATE login_attempts SET `timestamp` = attempt_time
     WHERE `timestamp` IS NULL AND attempt_time IS NOT NULL',
    'SELECT 1'
);
PREPARE copy_login_timestamp_stmt FROM @copy_login_timestamp;
EXECUTE copy_login_timestamp_stmt;
DEALLOCATE PREPARE copy_login_timestamp_stmt;

-- Rename the plural table only if the singular table does not exist.
SET @rename_suspicious_table := IF(
    EXISTS (
        SELECT 1 FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activities'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activity'
    ),
    'RENAME TABLE suspicious_activities TO suspicious_activity',
    'SELECT 1'
);
PREPARE rename_suspicious_table_stmt FROM @rename_suspicious_table;
EXECUTE rename_suspicious_table_stmt;
DEALLOCATE PREPARE rename_suspicious_table_stmt;

-- Ensure the PDF columns exist on the destination. Existing values and legacy
-- columns remain untouched.
SET @add_suspicious_username := IF(
    EXISTS (
        SELECT 1 FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activity'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activity'
          AND COLUMN_NAME = 'username'
    ),
    'ALTER TABLE suspicious_activity ADD COLUMN username VARCHAR(255) NULL',
    'SELECT 1'
);
PREPARE add_suspicious_username_stmt FROM @add_suspicious_username;
EXECUTE add_suspicious_username_stmt;
DEALLOCATE PREPARE add_suspicious_username_stmt;

SET @add_suspicious_ip := IF(
    EXISTS (
        SELECT 1 FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activity'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activity'
          AND COLUMN_NAME = 'ip_address'
    ),
    'ALTER TABLE suspicious_activity ADD COLUMN ip_address VARCHAR(255) NULL',
    'SELECT 1'
);
PREPARE add_suspicious_ip_stmt FROM @add_suspicious_ip;
EXECUTE add_suspicious_ip_stmt;
DEALLOCATE PREPARE add_suspicious_ip_stmt;

SET @add_suspicious_type := IF(
    EXISTS (
        SELECT 1 FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activity'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activity'
          AND COLUMN_NAME = 'activity_type'
    ),
    'ALTER TABLE suspicious_activity ADD COLUMN activity_type VARCHAR(100) NULL',
    'SELECT 1'
);
PREPARE add_suspicious_type_stmt FROM @add_suspicious_type;
EXECUTE add_suspicious_type_stmt;
DEALLOCATE PREPARE add_suspicious_type_stmt;

SET @copy_suspicious_type := IF(
    EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activity'
          AND COLUMN_NAME = 'activityType'
    ),
    'UPDATE suspicious_activity SET activity_type = activityType
     WHERE activity_type IS NULL AND activityType IS NOT NULL',
    'SELECT 1'
);
PREPARE copy_suspicious_type_stmt FROM @copy_suspicious_type;
EXECUTE copy_suspicious_type_stmt;
DEALLOCATE PREPARE copy_suspicious_type_stmt;

SET @add_suspicious_reason := IF(
    EXISTS (
        SELECT 1 FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activity'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activity'
          AND COLUMN_NAME = 'reason'
    ),
    'ALTER TABLE suspicious_activity ADD COLUMN reason TEXT NULL',
    'SELECT 1'
);
PREPARE add_suspicious_reason_stmt FROM @add_suspicious_reason;
EXECUTE add_suspicious_reason_stmt;
DEALLOCATE PREPARE add_suspicious_reason_stmt;

SET @add_suspicious_timestamp := IF(
    EXISTS (
        SELECT 1 FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activity'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activity'
          AND COLUMN_NAME = 'timestamp'
    ),
    'ALTER TABLE suspicious_activity ADD COLUMN `timestamp` DATETIME NULL',
    'SELECT 1'
);
PREPARE add_suspicious_timestamp_stmt FROM @add_suspicious_timestamp;
EXECUTE add_suspicious_timestamp_stmt;
DEALLOCATE PREPARE add_suspicious_timestamp_stmt;

-- Backfill null PDF columns from legacy columns only. Conflicting non-null
-- values remain in their original columns for explicit manual reconciliation.
SET @copy_suspicious_ip := IF(
    EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activity'
          AND COLUMN_NAME = 'ipAddress'
    ),
    'UPDATE suspicious_activity SET ip_address = ipAddress
     WHERE ip_address IS NULL AND ipAddress IS NOT NULL',
    'SELECT 1'
);
PREPARE copy_suspicious_ip_stmt FROM @copy_suspicious_ip;
EXECUTE copy_suspicious_ip_stmt;
DEALLOCATE PREPARE copy_suspicious_ip_stmt;

SET @copy_suspicious_reason := IF(
    EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activity'
          AND COLUMN_NAME = 'description'
    ),
    'UPDATE suspicious_activity SET reason = description
     WHERE reason IS NULL AND description IS NOT NULL',
    'SELECT 1'
);
PREPARE copy_suspicious_reason_stmt FROM @copy_suspicious_reason;
EXECUTE copy_suspicious_reason_stmt;
DEALLOCATE PREPARE copy_suspicious_reason_stmt;

SET @copy_suspicious_timestamp := IF(
    EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activity'
          AND COLUMN_NAME = 'detected_at'
    ),
    'UPDATE suspicious_activity SET `timestamp` = detected_at
     WHERE `timestamp` IS NULL AND detected_at IS NOT NULL',
    'SELECT 1'
);
PREPARE copy_suspicious_timestamp_stmt FROM @copy_suspicious_timestamp;
EXECUTE copy_suspicious_timestamp_stmt;
DEALLOCATE PREPARE copy_suspicious_timestamp_stmt;

-- Merge only when both table names exist. Original IDs are inserted explicitly.
-- Exact same-ID rows are skipped; a same-ID/different-data conflict raises a
-- duplicate-key error instead of silently remapping or discarding either row.
-- Keep the source table: this preserves source IDs and external references.
SET @source_has_id := EXISTS (
    SELECT 1 FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'suspicious_activities'
      AND COLUMN_NAME = 'id'
);
SET @target_has_id := EXISTS (
    SELECT 1 FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'suspicious_activity'
      AND COLUMN_NAME = 'id'
);
SET @source_username := IF(EXISTS (
    SELECT 1 FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activities'
      AND COLUMN_NAME = 'username'
), 'old.username', 'NULL');
SET @source_ip := IF(EXISTS (
    SELECT 1 FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activities'
      AND COLUMN_NAME = 'ip_address'
), IF(EXISTS (
    SELECT 1 FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activities'
      AND COLUMN_NAME = 'ipAddress'
), 'COALESCE(old.ip_address, old.ipAddress)', 'old.ip_address'), IF(EXISTS (
    SELECT 1 FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activities'
      AND COLUMN_NAME = 'ipAddress'
), 'old.ipAddress', 'NULL'));
SET @source_type := IF(EXISTS (
    SELECT 1 FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activities'
      AND COLUMN_NAME = 'activity_type'
), IF(EXISTS (
    SELECT 1 FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activities'
      AND COLUMN_NAME = 'activityType'
), 'COALESCE(old.activity_type, old.activityType)', 'old.activity_type'), IF(EXISTS (
    SELECT 1 FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activities'
      AND COLUMN_NAME = 'activityType'
), 'old.activityType', 'NULL'));
SET @source_reason := IF(EXISTS (
    SELECT 1 FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activities'
      AND COLUMN_NAME = 'reason'
), IF(EXISTS (
    SELECT 1 FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activities'
      AND COLUMN_NAME = 'description'
), 'COALESCE(old.reason, old.description)', 'old.reason'), IF(EXISTS (
    SELECT 1 FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activities'
      AND COLUMN_NAME = 'description'
), 'old.description', 'NULL'));
SET @source_timestamp := IF(EXISTS (
    SELECT 1 FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activities'
      AND COLUMN_NAME = 'timestamp'
), IF(EXISTS (
    SELECT 1 FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activities'
      AND COLUMN_NAME = 'detected_at'
), 'COALESCE(old.`timestamp`, old.detected_at)', 'old.`timestamp`'), IF(EXISTS (
    SELECT 1 FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activities'
      AND COLUMN_NAME = 'detected_at'
), 'old.detected_at', 'NULL'));

SET @merge_suspicious_tables := IF(
    EXISTS (
        SELECT 1 FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activities'
    ) AND EXISTS (
        SELECT 1 FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activity'
    ) AND @source_has_id AND @target_has_id,
    CONCAT(
        'INSERT INTO suspicious_activity ',
        '(id, username, ip_address, activity_type, reason, `timestamp`) ',
        'SELECT old.id, ', @source_username, ', ', @source_ip, ', ',
        @source_type, ', ', @source_reason, ', ', @source_timestamp,
        ' FROM suspicious_activities old ',
        'WHERE NOT EXISTS (SELECT 1 FROM suspicious_activity current ',
        'WHERE current.id = old.id ',
        'AND current.username <=> ', @source_username, ' ',
        'AND current.ip_address <=> ', @source_ip, ' ',
        'AND current.activity_type <=> ', @source_type, ' ',
        'AND current.reason <=> ', @source_reason, ' ',
        'AND current.`timestamp` <=> ', @source_timestamp, ')'
    ),
    IF(
        EXISTS (
            SELECT 1 FROM information_schema.TABLES
            WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activities'
        ) AND EXISTS (
            SELECT 1 FROM information_schema.TABLES
            WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'suspicious_activity'
        ) AND NOT (@source_has_id AND @target_has_id),
        'SELECT ''Cannot merge suspicious tables automatically: source or target id column is absent; source retained unchanged''',
        'SELECT 1'
    )
);
PREPARE merge_suspicious_tables_stmt FROM @merge_suspicious_tables;
EXECUTE merge_suspicious_tables_stmt;
DEALLOCATE PREPARE merge_suspicious_tables_stmt;
