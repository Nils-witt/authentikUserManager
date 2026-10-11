-- Requests by users to join a visible group. Pending requests are listed by
-- group for the operators deciding them, and by username for the requester.
CREATE TABLE group_join_requests (
    id         bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    group_pk   text        NOT NULL CHECK (group_pk <> ''),
    -- The group's name when the request was made, for display only.
    group_name text        NOT NULL,
    user_pk    integer     NOT NULL,
    username   text        NOT NULL CHECK (username <> ''),
    message    text        NOT NULL DEFAULT '',
    status     text        NOT NULL DEFAULT 'pending'
               CHECK (status IN ('pending', 'approved', 'rejected')),
    created_at timestamptz NOT NULL DEFAULT now(),
    decided_at timestamptz,
    decided_by text,
    CHECK ((status = 'pending') = (decided_at IS NULL))
);

-- One pending request per user and group; also serves the lookup by group.
CREATE UNIQUE INDEX group_join_requests_pending
    ON group_join_requests (group_pk, user_pk)
    WHERE status = 'pending';

CREATE INDEX group_join_requests_username ON group_join_requests (username);
