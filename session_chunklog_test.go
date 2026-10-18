package vaioidc

import (
	"log/slog"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestChunkedSessionLogLevel: a chunked write is the ordinary state of a session
// that retains tokens, so it logs at DEBUG; only a session nearing the chunk cap
// (sessionChunkWarnAt) logs at WARN, and a single-cookie session logs nothing.
func TestChunkedSessionLogLevel(t *testing.T) {
	key := testKey(t)
	payloadOfChunks := func(t *testing.T, want int) *sessionPayload {
		t.Helper()
		// Random-looking claim values defeat any compression, so size grows with the claim.
		for size := 0; size < maxCookieValueBytes*maxSessionCookieChunks; size += 200 {
			p := &sessionPayload{Sub: "u", Exp: time.Now().Add(time.Hour).Unix(), Claims: map[string]string{}}
			for i := 0; i*40 < size; i++ {
				p.Claims["k"+strconv.Itoa(i)] = strings.Repeat(strconv.Itoa(i*7919), 6)
			}
			enc, err := encryptSession(p, key)
			require.NoError(t, err)
			if n := len(chunkString(enc, maxCookieValueBytes)); n == want && len(enc) > maxCookieValueBytes {
				return p
			}
		}
		t.Fatalf("no payload of %d chunks", want)
		return nil
	}
	levelsFor := func(t *testing.T, p *sessionPayload) []slog.Level {
		rec := &recordingHandler{}
		require.NoError(t, setSessionCookie(httptest.NewRecorder(), p, key, "vai_test", "/", false, slog.New(rec)))
		var out []slog.Level
		for _, r := range rec.records {
			if r.Message == logMsgCookieLarge {
				out = append(out, r.Level)
			}
		}
		return out
	}

	single := &sessionPayload{Sub: "u", Exp: time.Now().Add(time.Hour).Unix()}
	assert.Empty(t, levelsFor(t, single), "a single-cookie session logs nothing")
	assert.Equal(t, []slog.Level{slog.LevelDebug}, levelsFor(t, payloadOfChunks(t, 2)), "two chunks is ordinary")
	assert.Equal(t, []slog.Level{slog.LevelDebug}, levelsFor(t, payloadOfChunks(t, sessionChunkWarnAt-1)))
	assert.Equal(t, []slog.Level{slog.LevelWarn}, levelsFor(t, payloadOfChunks(t, sessionChunkWarnAt)), "nearing the cap warns")
}
