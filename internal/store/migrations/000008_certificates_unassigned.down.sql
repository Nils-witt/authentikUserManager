DELETE FROM certificates WHERE user_pk IS NULL;
ALTER TABLE certificates
    DROP CONSTRAINT certificates_unassigned_check,
    DROP CONSTRAINT certificates_user_check,
    ALTER COLUMN user_pk SET NOT NULL,
    ALTER COLUMN username SET NOT NULL;
