package vaioidc_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/go-chi/chi/v5"

	vaioidc "github.com/vAudience/vai-oidc"
)

func ExampleUserFromContext() {
	// In a handler protected by RequireSession:
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := vaioidc.UserFromContext(r.Context())
		if user != nil {
			fmt.Printf("Hello, %s (%s)\n", user.Name, user.Email)
		}
	})

	// Simulate with test helper:
	testAuth := vaioidc.NewTestAuth(nil) // nil *testing.T safe for examples
	req := httptest.NewRequest("GET", "/dashboard", nil)
	req = testAuth.SetTestUser(req, &vaioidc.User{
		Sub:   "user-123",
		Email: "toni@vaudience.ai",
		Name:  "Toni",
	})

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	// Output: Hello, Toni (toni@vaudience.ai)
}

func ExampleAuth_Routes() {
	// Mount auth routes on a chi router.
	// (Uses test auth since we can't do real OIDC discovery in an example.)
	testAuth := vaioidc.NewTestAuth(nil)

	r := chi.NewRouter()
	r.Mount("/auth", testAuth.Routes())

	// Verify routes are registered.
	req := httptest.NewRequest("GET", "/auth/logout", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	fmt.Println(w.Code)
	// Output: 302
}

func ExampleTestAuth_TestSessionCookie() {
	// Create a test session cookie for middleware tests.
	testAuth := vaioidc.NewTestAuth(nil)

	user := &vaioidc.User{Sub: "test-user", Email: "dev@vaudience.ai", Name: "Dev"}
	cookie := testAuth.TestSessionCookie(nil, user)

	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(cookie)

	// The cookie will pass RequireSession middleware.
	var captured *vaioidc.User
	handler := testAuth.RequireSession()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = vaioidc.UserFromContext(r.Context())
	}))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	fmt.Printf("%s (%s)\n", captured.Name, captured.Email)
	// Output: Dev (dev@vaudience.ai)
}
