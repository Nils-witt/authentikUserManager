-- Notifications to users about changes to their account, kept until the user
-- deletes them. Pages are read newest first per user.
CREATE TABLE notifications (
    id         bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_pk    integer     NOT NULL,
    category   text        NOT NULL
               CHECK (category IN ('profile', 'certificate', 'join_request', 'settings')),
    header     text        NOT NULL CHECK (header <> ''),
    message    text        NOT NULL CHECK (message <> ''),
    created_at timestamptz NOT NULL DEFAULT now(),
    read_at    timestamptz
);

CREATE INDEX notifications_user ON notifications (user_pk, id DESC);
CREATE INDEX notifications_unread ON notifications (user_pk) WHERE read_at IS NULL;

-- Whether a user receives the notifications of a category on a channel. A
-- missing row means they do. Channels are not constrained, so new delivery
-- systems need no migration.
CREATE TABLE notification_preferences (
    user_pk  integer NOT NULL,
    category text    NOT NULL
             CHECK (category IN ('profile', 'certificate', 'join_request', 'settings')),
    channel  text    NOT NULL CHECK (channel <> ''),
    enabled  boolean NOT NULL,
    PRIMARY KEY (user_pk, category, channel)
);
