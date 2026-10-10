-- Append-only record of the changes operators make. Pages are read newest
-- first by id, which the primary key serves.
CREATE TABLE audit_log (
    id         bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT now(),
    actor      text        NOT NULL,
    action     text        NOT NULL CHECK (action <> ''),
    target     text        NOT NULL,
    details    jsonb       NOT NULL DEFAULT '{}'
);
