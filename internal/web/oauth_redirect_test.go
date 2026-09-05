package web

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/web/global"
)

func TestOAuthRootRedirect(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "x-ui.db")); err != nil {
		t.Fatalf("init db: %v", err)
	}
	t.Cleanup(func() { _ = database.CloseDB() })

	previous := global.GetWebServer()
	s := NewServer()
	s.cron = cron.New(cron.WithLocation(time.Local), cron.WithSeconds())
	global.SetWebServer(s)
	t.Cleanup(func() {
		s.cancel()
		global.SetWebServer(previous)
	})

	if err := s.settingService.SetBasePath("/custom-prefix/"); err != nil {
		t.Fatalf("set base path: %v", err)
	}

	engine, err := s.initRouter()
	if err != nil {
		t.Fatalf("init router: %v", err)
	}

	t.Run("redirects oauth callback to basePath with query", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=testcode&state=teststate", nil)
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		if w.Code != http.StatusTemporaryRedirect {
			t.Fatalf("expected status 307, got %d", w.Code)
		}
		expectedLoc := "/custom-prefix/oauth/callback?code=testcode&state=teststate"
		if loc := w.Header().Get("Location"); loc != expectedLoc {
			t.Fatalf("expected Location %q, got %q", expectedLoc, loc)
		}
	})

	t.Run("redirects oauth login to basePath", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/oauth/login", nil)
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		if w.Code != http.StatusTemporaryRedirect {
			t.Fatalf("expected status 307, got %d", w.Code)
		}
		expectedLoc := "/custom-prefix/oauth/login"
		if loc := w.Header().Get("Location"); loc != expectedLoc {
			t.Fatalf("expected Location %q, got %q", expectedLoc, loc)
		}
	})
}
