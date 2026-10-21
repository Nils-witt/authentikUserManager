-- Certificates the CA signed outside this application can be imported, so they
-- are listed and can be revoked. Their keys are unknown.
ALTER TABLE certificates
    DROP CONSTRAINT certificates_key_source_check,
    ADD CONSTRAINT certificates_key_source_check CHECK (key_source IN ('generated', 'csr', 'imported'));
