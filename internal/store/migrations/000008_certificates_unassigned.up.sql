-- Imported certificates may be assigned to no user, e.g. when their user was
-- deleted or never existed in authentik, so that they can still be revoked.
ALTER TABLE certificates
    ALTER COLUMN user_pk DROP NOT NULL,
    ALTER COLUMN username DROP NOT NULL,
    ADD CONSTRAINT certificates_user_check CHECK ((user_pk IS NULL) = (username IS NULL)),
    ADD CONSTRAINT certificates_unassigned_check CHECK (user_pk IS NOT NULL OR key_source = 'imported');
