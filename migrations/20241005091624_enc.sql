-- +goose Up
-- +goose StatementBegin
SELECT 'up SQL query';
CREATE TABLE IF NOT EXISTS encryption_keys (
    id SERIAL PRIMARY KEY,
    key_id UUID NOT NULL UNIQUE,
    encrypted_key_material BYTEA NOT NULL,
    creation_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expiration_date TIMESTAMP WITH TIME ZONE,
    status VARCHAR(10) CHECK (status IN ('ACTIVE', 'INACTIVE', 'ROTATED')),
    version INTEGER NOT NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';
DROP TABLE IF EXISTS encryption_keys;
-- +goose StatementEnd
