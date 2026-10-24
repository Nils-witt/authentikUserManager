DROP INDEX certificates_revoked;
CREATE INDEX certificates_revoked ON certificates (not_after) WHERE revoked_at IS NOT NULL;
ALTER TABLE certificates DROP COLUMN ca_id;
DROP TABLE certificate_authorities;
