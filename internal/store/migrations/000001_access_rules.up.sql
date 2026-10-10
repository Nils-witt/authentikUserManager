-- One row per (operator group, target group) pair: members of operator_group
-- may manage members of target_group ('*' for all users).
CREATE TABLE access_rules (
    operator_group text        NOT NULL CHECK (operator_group <> ''),
    target_group   text        NOT NULL CHECK (target_group <> ''),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    updated_by     text        NOT NULL,
    -- Also serves the lookup by operator_group.
    PRIMARY KEY (operator_group, target_group)
);
