package repository

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/valu/encrpytion/internal/model"
)

type DB struct {
	*sql.DB
}

func New(db *sql.DB) *DB {
	return &DB{DB: db}
}

func (db *DB) CreateKey(ctx context.Context, key *model.EncryptionKey) error {
	query := `
		INSERT INTO encryption_keys (key_id, encrypted_key_material, creation_date, expiration_date, status, version)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id`
	err := db.QueryRowContext(ctx, query,
		key.KeyID, key.EncryptedKeyMaterial, key.CreationDate, key.ExpirationDate, key.Status, key.Version,
	).Scan(&key.ID)
	return err
}

func (db *DB) GetKey(ctx context.Context, keyID uuid.UUID) (*model.EncryptionKey, error) {
	query := `
		SELECT id, key_id, encrypted_key_material, creation_date, expiration_date, status, version
		FROM encryption_keys
		WHERE key_id = $1`
	var key model.EncryptionKey
	err := db.QueryRowContext(ctx, query, keyID).Scan(
		&key.ID, &key.KeyID, &key.EncryptedKeyMaterial, &key.CreationDate, &key.ExpirationDate, &key.Status, &key.Version,
	)
	if err != nil {
		return nil, err
	}
	return &key, nil
}

func (db *DB) ListActiveKeys(ctx context.Context) ([]*model.EncryptionKey, error) {
	query := `
		SELECT id, key_id, encrypted_key_material, creation_date, expiration_date, status, version
		FROM encryption_keys
		WHERE status = 'ACTIVE'
		ORDER BY creation_date DESC`
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []*model.EncryptionKey
	for rows.Next() {
		var key model.EncryptionKey
		err := rows.Scan(
			&key.ID, &key.KeyID, &key.EncryptedKeyMaterial, &key.CreationDate, &key.ExpirationDate, &key.Status, &key.Version,
		)
		if err != nil {
			return nil, err
		}
		keys = append(keys, &key)
	}
	return keys, nil
}

func (db *DB) GetAllKeyVersions(ctx context.Context) (map[uint32]*model.EncryptionKey, error) {
	query := `
		SELECT id, key_id, encrypted_key_material, creation_date, expiration_date, status, version
		FROM encryption_keys
		ORDER BY version`
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keyVersions := make(map[uint32]*model.EncryptionKey)
	for rows.Next() {
		var key model.EncryptionKey
		err := rows.Scan(
			&key.ID, &key.KeyID, &key.EncryptedKeyMaterial, &key.CreationDate, &key.ExpirationDate, &key.Status, &key.Version,
		)
		if err != nil {
			return nil, err
		}
		keyVersions[uint32(key.Version)] = &key
	}
	return keyVersions, nil
}

func (db *DB) GetCurrentActiveKey(ctx context.Context) (*model.EncryptionKey, error) {
	query := `
		SELECT id, key_id, encrypted_key_material, creation_date, expiration_date, status, version
		FROM encryption_keys
		WHERE status = 'ACTIVE'
		ORDER BY version DESC
		LIMIT 1`
	var key model.EncryptionKey
	err := db.QueryRowContext(ctx, query).Scan(
		&key.ID, &key.KeyID, &key.EncryptedKeyMaterial, &key.CreationDate, &key.ExpirationDate, &key.Status, &key.Version,
	)
	if err != nil {
		return nil, err
	}
	return &key, nil
}

func (db *DB) RotateKey(ctx context.Context, oldKeyID uuid.UUID, newKey *model.EncryptionKey) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Update old key status
	_, err = tx.ExecContext(ctx,
		`UPDATE encryption_keys SET status = $1 WHERE key_id = $2`,
		string(model.KeyStatusRotated), oldKeyID)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO encryption_keys (key_id, encrypted_key_material, creation_date, expiration_date, status, version)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		newKey.KeyID, newKey.EncryptedKeyMaterial, newKey.CreationDate, newKey.ExpirationDate, newKey.Status, newKey.Version)
	if err != nil {
		return err
	}

	return tx.Commit()
}
