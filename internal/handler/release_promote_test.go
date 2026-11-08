package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/tabloy/keygate/internal/model"
	"github.com/tabloy/keygate/internal/service"
	"github.com/tabloy/keygate/internal/store"
)

const (
	promoteTestSlug     = "promote-product"
	promoteTestPlatform = "darwin-arm64"
	promoteTestSig      = "c2lnbmF0dXJlLW9mLXRoZS1ieXRlcw=="
)

type promoteFixture struct {
	router    *gin.Engine
	store     *store.Store
	service   *service.ReleaseService
	productID string
}

func setupPromoteTest(t *testing.T) *promoteFixture {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	s, err := store.New(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.RunMigrations("../../db/migrations"); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	cleanup := func() {
		_, _ = s.DB.NewRaw("DELETE FROM audit_logs WHERE entity = 'release' AND entity_id IN (SELECT r.id FROM releases r JOIN products p ON p.id = r.product_id WHERE p.slug = ?)", promoteTestSlug).Exec(ctx)
		_, _ = s.DB.NewRaw("DELETE FROM releases WHERE product_id IN (SELECT id FROM products WHERE slug = ?)", promoteTestSlug).Exec(ctx)
		_, _ = s.DB.NewRaw("DELETE FROM products WHERE slug = ?", promoteTestSlug).Exec(ctx)
	}
	cleanup()
	t.Cleanup(cleanup)

	productID := store.NewID()
	if _, err := s.DB.NewRaw(
		"INSERT INTO products (id, name, slug, type, created_at) VALUES (?, 'Promote Product', ?, 'desktop', now())",
		productID, promoteTestSlug).Exec(ctx); err != nil {
		t.Fatal(err)
	}

	gin.SetMode(gin.TestMode)
	svc := service.NewReleaseService(service.ReleaseServiceConfig{Store: s})
	h := NewReleaseAdminHandler(svc, s)
	router := gin.New()
	router.GET("/releases", h.List)
	router.POST("/releases/:id/actions/promote", h.Promote)

	return &promoteFixture{router: router, store: s, service: svc, productID: productID}
}

// seedRelease inserts a release in the given state, as if it had been
// uploaded, signed and published a week ago.
func (f *promoteFixture) seedRelease(t *testing.T, version, channel, status string) *model.Release {
	t.Helper()
	ctx := context.Background()
	rel := &model.Release{ProductID: f.productID, Version: version, Channel: channel}
	if err := f.store.CreateRelease(ctx, rel); err != nil {
		t.Fatal(err)
	}
	artifact := &model.ReleaseArtifact{ReleaseID: rel.ID, Platform: promoteTestPlatform}
	if err := f.store.CreateArtifact(ctx, artifact); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB.NewRaw(
		"UPDATE release_artifacts SET file_key = ?, file_size = 42, sha256 = ?, ed25519_sig = ? WHERE id = ?",
		"releases/"+version+".dmg", strings.Repeat("a", 64), promoteTestSig, artifact.ID).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if status != model.ReleaseStatusDraft {
		if _, err := f.store.DB.NewRaw(
			"UPDATE releases SET status = ?, published_at = now() - interval '7 days' WHERE id = ?",
			status, rel.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
	return rel
}

func (f *promoteFixture) promote(releaseID, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/releases/"+releaseID+"/actions/promote", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

func (f *promoteFixture) feedVersions(t *testing.T, channel string) []string {
	t.Helper()
	releases, err := f.service.ListForFeed(context.Background(), f.productID, channel, promoteTestPlatform, 50)
	if err != nil {
		t.Fatal(err)
	}
	versions := make([]string, 0, len(releases))
	for _, r := range releases {
		versions = append(versions, r.Version)
	}
	return versions
}

func TestPromoteMovesBetaReleaseToStableFeed(t *testing.T) {
	f := setupPromoteTest(t)
	ctx := context.Background()
	rel := f.seedRelease(t, "1.12.900", model.ReleaseChannelBeta, model.ReleaseStatusPublished)
	before, err := f.store.FindReleaseByID(ctx, rel.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.feedVersions(t, model.ReleaseChannelStable); len(got) != 0 {
		t.Fatalf("stable feed before promotion = %v, want empty", got)
	}

	w := f.promote(rel.ID, `{"channel":"stable"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("promote = %d: %s", w.Code, w.Body.String())
	}

	after, err := f.store.FindReleaseByID(ctx, rel.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Channel != model.ReleaseChannelStable {
		t.Errorf("channel = %q, want stable", after.Channel)
	}
	if after.Status != model.ReleaseStatusPublished {
		t.Errorf("status = %q, want published", after.Status)
	}
	if !after.PublishedAt.After(before.PublishedAt.Add(24 * time.Hour)) {
		t.Errorf("published_at = %v, want it moved on from %v", after.PublishedAt, before.PublishedAt)
	}

	// The whole point: the same artifact, not a rebuilt or re-signed one.
	if len(after.Artifacts) != 1 {
		t.Fatalf("artifacts = %d, want 1", len(after.Artifacts))
	}
	if a, b := after.Artifacts[0], before.Artifacts[0]; a.ID != b.ID || a.FileKey != b.FileKey ||
		a.SHA256 != b.SHA256 || a.Ed25519Sig != promoteTestSig {
		t.Errorf("artifact changed: before %+v, after %+v", b, a)
	}

	if got := f.feedVersions(t, model.ReleaseChannelStable); len(got) != 1 || got[0] != "1.12.900" {
		t.Errorf("stable feed = %v, want [1.12.900]", got)
	}
	// Feeds are inclusive downward, so beta subscribers still see it.
	if got := f.feedVersions(t, model.ReleaseChannelBeta); len(got) != 1 || got[0] != "1.12.900" {
		t.Errorf("beta feed = %v, want [1.12.900]", got)
	}

	// Store.Audit writes from a goroutine, so give it a moment.
	var actions int
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if err := f.store.DB.NewRaw(
			"SELECT count(*) FROM audit_logs WHERE entity = 'release' AND entity_id = ? AND action = 'promoted'",
			rel.ID).Scan(ctx, &actions); err != nil {
			t.Fatal(err)
		}
		if actions > 0 {
			break
		}
	}
	if actions != 1 {
		t.Errorf("promoted audit rows = %d, want 1", actions)
	}
}

func TestPromoteRefusals(t *testing.T) {
	f := setupPromoteTest(t)
	published := model.ReleaseStatusPublished

	cases := []struct {
		name          string
		version       string
		channel       string
		status        string
		body          string
		wantStatus    int
		wantErrorCode string
	}{
		{"same channel", "1.12.901", "beta", published, `{"channel":"beta"}`, 409, "CHANNEL_NOT_WIDER"},
		{"narrower channel", "1.12.902", "stable", published, `{"channel":"beta"}`, 409, "CHANNEL_NOT_WIDER"},
		{"draft", "1.12.903", "beta", model.ReleaseStatusDraft, `{"channel":"stable"}`, 409, "NOT_PROMOTABLE"},
		{"yanked", "1.12.904", "beta", model.ReleaseStatusYanked, `{"channel":"stable"}`, 409, "NOT_PROMOTABLE"},
		{"unknown channel", "1.12.905", "beta", published, `{"channel":"nightly"}`, 400, "INVALID_CHANNEL"},
		{"missing channel", "1.12.906", "beta", published, `{}`, 400, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rel := f.seedRelease(t, tc.version, tc.channel, tc.status)

			w := f.promote(rel.ID, tc.body)
			if w.Code != tc.wantStatus {
				t.Fatalf("promote = %d, want %d: %s", w.Code, tc.wantStatus, w.Body.String())
			}
			if tc.wantErrorCode != "" && !strings.Contains(w.Body.String(), tc.wantErrorCode) {
				t.Errorf("body = %s, want error %s", w.Body.String(), tc.wantErrorCode)
			}

			after, err := f.store.FindReleaseByID(context.Background(), rel.ID)
			if err != nil {
				t.Fatal(err)
			}
			if after.Channel != tc.channel {
				t.Errorf("channel = %q after a refused promotion, want %q", after.Channel, tc.channel)
			}
		})
	}

	t.Run("unknown release", func(t *testing.T) {
		if w := f.promote(store.NewID(), `{"channel":"stable"}`); w.Code != http.StatusNotFound {
			t.Errorf("promote = %d, want 404: %s", w.Code, w.Body.String())
		}
	})
}

func TestListReleasesFiltersByVersion(t *testing.T) {
	f := setupPromoteTest(t)
	f.seedRelease(t, "1.12.910", model.ReleaseChannelBeta, model.ReleaseStatusPublished)
	f.seedRelease(t, "1.12.911", model.ReleaseChannelBeta, model.ReleaseStatusPublished)

	req := httptest.NewRequest(http.MethodGet, "/releases?product_id="+f.productID+"&version=1.12.911", nil)
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("list = %d: %s", w.Code, w.Body.String())
	}

	var body struct {
		Data struct {
			Releases []model.Release `json:"releases"`
			Total    int             `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Data.Total != 1 || len(body.Data.Releases) != 1 || body.Data.Releases[0].Version != "1.12.911" {
		t.Errorf("list = %+v, want only 1.12.911", body.Data)
	}
}
