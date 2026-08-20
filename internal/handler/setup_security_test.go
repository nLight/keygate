package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/tabloy/keygate/internal/store"
)

func TestSetupInitializeConcurrentExactlyOnce(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}

	s, err := store.New(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.RunMigrations("../../db/migrations"); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	cleanup := func() {
		_, _ = s.DB.NewRaw("DELETE FROM plans WHERE product_id IN (SELECT id FROM products WHERE slug = 'setup-race-product')").Exec(ctx)
		_, _ = s.DB.NewRaw("DELETE FROM products WHERE slug = 'setup-race-product'").Exec(ctx)
		_, _ = s.DB.NewRaw("DELETE FROM users WHERE email = 'setup-race@example.com'").Exec(ctx)
		_, _ = s.DB.NewRaw("DELETE FROM settings WHERE key IN ('setup_complete', 'setup_bootstrap_consumed_at', 'site_name')").Exec(ctx)
	}
	cleanup()
	t.Cleanup(cleanup)

	const secret = "bootstrap-secret-with-at-least-32-characters"
	h := NewSetupHandler(s, SetupOptions{Enabled: true, BootstrapSecret: secret})
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/v1/setup/initialize", h.Initialize)
	body := `{"bootstrap_secret":"` + secret + `","admin_email":"setup-race@example.com","admin_name":"Owner","site_name":"Keygate","product_name":"Race Product","product_slug":"setup-race-product","product_type":"desktop"}`
	send := func(requestBody string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/setup/initialize", bytes.NewBufferString(requestBody))
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		return recorder
	}
	if w := send(strings.Replace(body, secret, "wrong-bootstrap-secret-with-32-characters", 1)); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret status=%d body=%s", w.Code, w.Body.String())
	}
	if w := send(`{"admin_email":"setup-race@example.com","admin_name":"Owner","site_name":"Keygate","product_name":"Race Product","product_slug":"setup-race-product","product_type":"desktop"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("missing secret status=%d body=%s", w.Code, w.Body.String())
	}

	start := make(chan struct{})
	statuses := make(chan int, 2)
	responses := make(chan string, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			recorder := send(body)
			statuses <- recorder.Code
			responses <- recorder.Body.String()
		}()
	}
	close(start)
	wg.Wait()
	close(statuses)
	close(responses)

	gotStatuses := make([]int, 0, 2)
	for status := range statuses {
		gotStatuses = append(gotStatuses, status)
	}
	sort.Ints(gotStatuses)
	if len(gotStatuses) != 2 || gotStatuses[0] != http.StatusCreated || gotStatuses[1] != http.StatusConflict {
		t.Fatalf("statuses = %v, want [%d %d]", gotStatuses, http.StatusCreated, http.StatusConflict)
	}
	for responseBody := range responses {
		if strings.Contains(responseBody, secret) {
			t.Fatal("bootstrap secret leaked in setup response")
		}
	}

	var owners, products, plans int
	if err := s.DB.NewRaw("SELECT count(*) FROM users WHERE email = ? AND role = 'owner'", "setup-race@example.com").Scan(ctx, &owners); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.NewRaw("SELECT count(*) FROM products WHERE slug = ?", "setup-race-product").Scan(ctx, &products); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.NewRaw("SELECT count(*) FROM plans WHERE product_id IN (SELECT id FROM products WHERE slug = ?)", "setup-race-product").Scan(ctx, &plans); err != nil {
		t.Fatal(err)
	}
	if owners != 1 || products != 1 || plans != 1 {
		t.Fatalf("committed rows: owners=%d products=%d plans=%d, want exactly one of each", owners, products, plans)
	}
}
