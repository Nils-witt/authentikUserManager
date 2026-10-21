DELETE FROM certificates WHERE key_source = 'imported';
ALTER TABLE certificates
    DROP CONSTRAINT certificates_key_source_check,
    ADD CONSTRAINT certificates_key_source_check CHECK (key_source IN ('generated', 'csr'));
