-- API keys with which service accounts issue and revoke their own
-- certificates. Only the SHA-256 hash of a key is stored; the key is shown
-- once when it is created.
CREATE TABLE api_keys (
    id           bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_pk      integer     NOT NULL,
    username     text        NOT NULL CHECK (username <> ''),
    description  text        NOT NULL,
    -- The beginning of the key, to tell keys apart.
    start        text        NOT NULL CHECK (start <> ''),
    key_hash     bytea       NOT NULL UNIQUE CHECK (length(key_hash) = 32),
    created_at   timestamptz NOT NULL DEFAULT now(),
    created_by   text        NOT NULL CHECK (created_by <> ''),
    expires_at   timestamptz,
    last_used_at timestamptz
);

CREATE INDEX api_keys_user_pk ON api_keys (user_pk, id DESC);
