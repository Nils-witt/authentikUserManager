-- Serves the list of all certificates, newest first, for access administrators.
CREATE INDEX certificates_issued_at ON certificates (issued_at DESC, serial);
