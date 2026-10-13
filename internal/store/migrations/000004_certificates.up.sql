-- Client certificates issued to users by the configured CA. Private keys are
-- never stored. Revoked certificates are listed in the CRL until they expire.
CREATE TABLE certificates (
    -- Lowercase hex serial number, as formatted by pki.SerialText.
    serial     text        PRIMARY KEY CHECK (serial ~ '^[0-9a-f]+$'),
    user_pk    integer     NOT NULL,
    username   text        NOT NULL CHECK (username <> ''),
    subject    text        NOT NULL,
    not_before timestamptz NOT NULL,
    not_after  timestamptz NOT NULL,
    issued_at  timestamptz NOT NULL DEFAULT now(),
    issued_by  text        NOT NULL CHECK (issued_by <> ''),
    key_source text        NOT NULL CHECK (key_source IN ('generated', 'csr')),
    revoked_at timestamptz,
    revoked_by text,
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);

CREATE INDEX certificates_user_pk ON certificates (user_pk, issued_at DESC);

-- Serves the CRL, which lists the revoked certificates that have not expired.
CREATE INDEX certificates_revoked ON certificates (not_after) WHERE revoked_at IS NOT NULL;
