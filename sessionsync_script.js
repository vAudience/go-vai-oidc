/*
 * vaioidc session-sync client — the BROWSER half of identity reconciliation.
 *
 * ⛔ THIS FILE IS SERVED BY go-vai-oidc, NOT COPIED INTO CONSUMERS, AND THAT IS
 * THE POINT. Between v0.20.0 and v0.21.0 the only working implementation lived
 * as a 158-line hand-written copy in one consumer, about to be copied into eight
 * more. The browser half is precisely the half with no server-side signal: a
 * copy that drifts, or one that is never updated when a verdict is added, fails
 * in a browser console and nowhere else. One owner, reached by a pin bump.
 *
 * WHY IT EXISTS, and why it is not "poll harder":
 *
 * The server-side revalidation floor (Config.RevalidateInterval) asks the token
 * endpoint "is the session this cookie was minted from still alive?", using a
 * refresh token bound to THAT session. When somebody signs in as a DIFFERENT
 * person, Keycloak mints a NEW session and swaps the browser's identity cookie
 * WITHOUT terminating the old one — so the floor asks about the old session,
 * Keycloak truthfully answers "still alive", and the refreshed tokens come back
 * carrying the OLD person's subject. The product keeps serving the previous
 * user, correctly, indefinitely. No interval fixes that: the axis is the
 * QUESTION, not the frequency.
 *
 * Only a request that travels through the BROWSER carries the browser's Keycloak
 * cookie. This file makes that request, in a hidden same-origin iframe, and acts
 * on the verdict.
 *
 * ⛔ IT MUST NOT NAVIGATE TO LOGIN on a `switched` verdict. That would silently
 * adopt the new identity, which is exactly the surprise this reports instead of
 * performing (operator decision 2026-09-11: a tab must not change owner
 * underneath unsaved work). A reload renders the product's own signed-out state
 * and the person chooses.
 */
(function () {
  "use strict";

  // Both endpoints are templated in by the handler that serves this file, from
  // the mount the consumer actually chose. ⛔ Never transcribed by a consumer and
  // never guessed here: a script that assumes "/auth" is a script that is wrong
  // on every consumer that mounted anywhere else, silently.
  var ENDPOINT = __VAIOIDC_SYNC_ENDPOINT__;
  var BLOCKED_ENDPOINT = __VAIOIDC_BLOCKED_ENDPOINT__;

  var TIMER_MS = 5 * 60 * 1000;
  // A frame that never reports is the CSP-blocked case (frame-src missing, or a
  // provider that did not redirect). Reaping it bounds the damage to one hidden
  // iframe rather than one per focus event, forever.
  var TIMEOUT_MS = 20 * 1000;
  // After this many consecutive silent runs, stop and TELL THE SERVER. A
  // permanently blocked frame is a deployment defect that no amount of retrying
  // repairs, and retrying it on every focus is how a silent defect becomes a
  // visible leak.
  var MAX_SILENT = 3;

  var inFlight = false;
  var stopped = false;
  var silentRuns = 0;
  var timerID = null;

  function stop() {
    stopped = true;
    if (timerID !== null) {
      clearInterval(timerID);
      timerID = null;
    }
  }

  // ⭐ THE ONLY REPORT THIS FAILURE HAS. Everything above this line fails in a
  // browser console: a missing `frame-src` directive, a consumer middleware that
  // overwrites the sync document's CSP, a provider that renders instead of
  // redirecting. Each leaves the product serving the previous user with every
  // server-side signal green — the exact shape that cost this fleet two silent
  // outages. One beacon converts it into a server log line.
  function reportBlocked() {
    try {
      var body = JSON.stringify({ reason: "no_verdict", runs: silentRuns });
      if (navigator.sendBeacon) {
        navigator.sendBeacon(BLOCKED_ENDPOINT, new Blob([body], { type: "text/plain" }));
        return;
      }
      var xhr = new XMLHttpRequest();
      xhr.open("POST", BLOCKED_ENDPOINT, true);
      xhr.setRequestHeader("Content-Type", "text/plain");
      xhr.send(body);
    } catch (e) {
      /* the report is best-effort; never let it break the page */
    }
  }

  function act(result) {
    silentRuns = 0;
    // `disabled` is the server telling us this deployment did not opt in. It is
    // a truthful answer, not a failure — and re-asking it every five minutes
    // forever would be.
    if (result === "disabled") {
      stop();
      return;
    }
    // The session cookie is already gone server-side on both closing verdicts,
    // so a reload renders the signed-out page.
    if (result === "switched" || result === "signed_out") {
      window.location.reload();
    }
  }

  function sync() {
    if (stopped || inFlight || document.hidden) {
      return;
    }
    inFlight = true;

    var frame = document.createElement("iframe");
    frame.hidden = true;
    frame.setAttribute("aria-hidden", "true");
    frame.setAttribute("title", "session sync");
    frame.style.display = "none";

    var settled = false;
    var timer = null;

    function finish(result) {
      if (settled) {
        return;
      }
      settled = true;
      inFlight = false;
      if (timer !== null) {
        window.clearTimeout(timer);
      }
      window.removeEventListener("message", onMessage);
      if (frame.parentNode) {
        frame.parentNode.removeChild(frame);
      }
      if (result) {
        act(result);
        return;
      }
      silentRuns += 1;
      if (silentRuns >= MAX_SILENT) {
        stop();
        reportBlocked();
      }
    }

    function onMessage(event) {
      if (event.origin !== window.location.origin) {
        return;
      }
      var d = event.data;
      if (!d || d.source !== "vaioidc" || d.type !== "session-sync") {
        return;
      }
      finish(d.result);
    }

    window.addEventListener("message", onMessage);

    // Fallback for a consumer CSP that strips the document's inline script: the
    // verdict is also written to <html data-vaioidc-sync-result>, readable
    // because the final document is same-origin.
    frame.onload = function () {
      try {
        var el = frame.contentDocument && frame.contentDocument.documentElement;
        if (el && el.dataset && el.dataset.vaioidcSyncResult) {
          finish(el.dataset.vaioidcSyncResult);
        }
      } catch (e) {
        /* still on the provider's origin mid-flight — not an error */
      }
    };

    timer = window.setTimeout(function () {
      finish(null);
    }, TIMEOUT_MS);

    frame.src = ENDPOINT;
    document.body.appendChild(frame);
  }

  // On focus catches exactly the case this exists for: the person switched
  // accounts in another tab and came back to this one.
  window.addEventListener("focus", sync);
  document.addEventListener("visibilitychange", function () {
    if (!document.hidden) {
      sync();
    }
  });
  // The timer is an ADDITION, never the primary signal — browsers throttle
  // background timers, so it covers only a focused idle tab.
  timerID = window.setInterval(sync, TIMER_MS);

  // Exposed so an API client's 401 trap can reconcile before navigating to
  // login: a 401 caused by a switched identity should show the signed-out page,
  // not silently sign the browser's current person in.
  window.vaioidcSessionSync = sync;

  sync();
})();
