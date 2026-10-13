-- The DER encoding of each certificate issued from now on, so access
-- administrators can download it. It holds no private key. Certificates issued
-- before this migration have none.
ALTER TABLE certificates ADD COLUMN der bytea;
