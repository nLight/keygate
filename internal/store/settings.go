package store

import (
	"context"

	"github.com/uptrace/bun"
)

type Setting struct {
	bun.BaseModel `bun:"table:settings"`
	Key           string `bun:",pk" json:"key"`
	Value         string `json:"value"`
}

func (s *Store) GetSetting(ctx context.Context, key string) (string, error) {
	setting := new(Setting)
	err := s.DB.NewSelect().Model(setting).Where("key = ?", key).Scan(ctx)
	if err != nil {
		return "", err
	}
	return setting.Value, nil
}

func (s *Store) GetSettings(ctx context.Context) (map[string]string, error) {
	var settings []Setting
	err := s.DB.NewSelect().Model(&settings).Scan(ctx)
	if err != nil {
		return nil, err
	}
	result := make(map[string]string, len(settings))
	for _, s := range settings {
		result[s.Key] = s.Value
	}
	return result, nil
}

// GetPublicSettings returns settings safe for unauthenticated access (site branding).
func (s *Store) GetPublicSettings(ctx context.Context) (map[string]string, error) {
	publicKeys := []string{"site_name", "timezone", "brand_color", "language", "logo_url"}
	var settings []Setting
	err := s.DB.NewSelect().Model(&settings).
		Where("key IN (?)", bun.In(publicKeys)).Scan(ctx)
	if err != nil {
		return nil, err
	}
	result := make(map[string]string, len(settings))
	for _, s := range settings {
		result[s.Key] = s.Value
	}
	return result, nil
}

func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	return upsertSetting(ctx, s.DB, key, value)
}

// SetSettings writes all settings in one transaction, so values that only
// make sense together (e.g. a webhook endpoint ID and its signing secret)
// are never persisted half-updated.
func (s *Store) SetSettings(ctx context.Context, settings map[string]string) error {
	return s.DB.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		for key, value := range settings {
			if err := upsertSetting(ctx, tx, key, value); err != nil {
				return err
			}
		}
		return nil
	})
}

func upsertSetting(ctx context.Context, db bun.IDB, key, value string) error {
	setting := &Setting{Key: key, Value: value}
	_, err := db.NewInsert().Model(setting).
		On("CONFLICT (key) DO UPDATE").
		Set("value = EXCLUDED.value").
		Exec(ctx)
	return err
}
