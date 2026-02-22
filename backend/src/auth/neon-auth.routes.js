/**
 * Neon Auth routes — sign-up/sign-in via Neon's managed auth (Better Auth)
 *
 * Flow: Desktop/client → our backend → Neon Auth API → create/link local user → return our JWT
 * OAuth: Desktop → browser → our backend → Neon Auth social → Google/GitHub → Neon Auth callback → our bridge page → JWT
 */

const express = require("express");
const https = require("https");
const crypto = require("crypto");
const { getDb } = require("../db/database");
const { generateToken } = require("./middleware");

const router = express.Router();

const NEON_AUTH_URL = (
  process.env.NEON_AUTH_URL ||
  "https://ep-odd-shape-ailpstvi.neonauth.c-4.us-east-1.aws.neon.tech/neondb/auth"
).trim();

const NEON_AUTH_ORIGIN = (
  process.env.NEON_AUTH_ORIGIN || "https://pcremote-backend-ashen.vercel.app"
).trim();

// ─── Pending Neon OAuth sessions ─────────────────────────────────────────────

const pendingNeonOAuth = new Map();

// Cleanup expired entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of pendingNeonOAuth) {
    if (val.expiresAt < now) pendingNeonOAuth.delete(key);
  }
}, 5 * 60 * 1000);

function generateOAuthCode() {
  return crypto.randomBytes(16).toString("hex");
}

// ─── Helper: HTTPS JSON request ──────────────────────────────────────────────

function neonAuthRequest(path, body) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, NEON_AUTH_URL);
    const data = JSON.stringify(body);

    const reqOptions = {
      hostname: url.hostname,
      path: url.pathname,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        Origin: NEON_AUTH_ORIGIN,
        "Content-Length": Buffer.byteLength(data),
      },
    };

    const req = https.request(reqOptions, (res) => {
      let raw = "";
      res.on("data", (chunk) => (raw += chunk));
      res.on("end", () => {
        try {
          const parsed = JSON.parse(raw);
          resolve({ status: res.statusCode, data: parsed });
        } catch {
          resolve({ status: res.statusCode, data: raw });
        }
      });
    });
    req.on("error", reject);
    req.write(data);
    req.end();
  });
}

// ─── Helper: HTTPS request capturing redirects ──────────────────────────────

function neonAuthSocialRequest(fullUrl, body) {
  return new Promise((resolve, reject) => {
    const url = new URL(fullUrl);
    const data = JSON.stringify(body);

    const reqOptions = {
      hostname: url.hostname,
      path: url.pathname + url.search,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        Origin: NEON_AUTH_ORIGIN,
        "Content-Length": Buffer.byteLength(data),
      },
    };

    const req = https.request(reqOptions, (res) => {
      // Capture redirect
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        resolve({ redirect: true, url: res.headers.location, status: res.statusCode, headers: res.headers });
        res.resume(); // consume response body
        return;
      }

      let raw = "";
      res.on("data", (chunk) => (raw += chunk));
      res.on("end", () => {
        try {
          const parsed = JSON.parse(raw);
          resolve({ redirect: false, data: parsed, status: res.statusCode, headers: res.headers });
        } catch {
          resolve({ redirect: false, data: raw, status: res.statusCode, headers: res.headers });
        }
      });
    });
    req.on("error", reject);
    req.write(data);
    req.end();
  });
}

// ─── Find or create local user from Neon Auth user ──────────────────────────

async function findOrCreateFromNeonAuth(neonUser) {
  const prisma = getDb();

  // Try to find by oauthProvider=neon + oauthId=neonAuthId
  const existing = await prisma.user.findFirst({
    where: { oauthProvider: "neon", oauthId: neonUser.id },
  });
  if (existing) return existing;

  // Check if email matches an existing user → link accounts
  if (neonUser.email) {
    const byEmail = await prisma.user.findUnique({
      where: { email: neonUser.email },
    });
    if (byEmail) {
      const updated = await prisma.user.update({
        where: { id: byEmail.id },
        data: { oauthProvider: "neon", oauthId: neonUser.id },
      });
      return updated;
    }
  }

  // Create new user with unique username
  const safeName = neonUser.name || neonUser.email.split("@")[0] || "neonuser";
  let finalName = safeName;
  let counter = 1;
  while (true) {
    const dup = await prisma.user.findUnique({
      where: { username: finalName },
    });
    if (!dup) break;
    finalName = `${safeName}_${counter++}`;
  }

  const user = await prisma.user.create({
    data: {
      username: finalName,
      email: neonUser.email || `${finalName}@neon.local`,
      password: "",
      oauthProvider: "neon",
      oauthId: neonUser.id,
    },
  });
  return user;
}

// ═════════════════════════════════════════════════════════════════════════════
// POST /api/auth/neon/signup
// Body: { name, email, password }
// ═════════════════════════════════════════════════════════════════════════════

router.post("/neon/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "email and password are required",
        timestamp: new Date().toISOString(),
      });
    }
    if (password.length < 8) {
      return res.status(400).json({
        error: "Password must be at least 8 characters (Neon Auth requirement)",
        timestamp: new Date().toISOString(),
      });
    }

    // Call Neon Auth sign-up
    const result = await neonAuthRequest(NEON_AUTH_URL + "/sign-up/email", {
      name: name || email.split("@")[0],
      email,
      password,
    });

    if (result.status !== 200 || !result.data.user) {
      const errMsg =
        result.data?.message || result.data?.error || "Neon Auth sign-up failed";
      return res.status(result.status === 200 ? 500 : result.status).json({
        error: errMsg,
        timestamp: new Date().toISOString(),
      });
    }

    // Create/link local user
    const localUser = await findOrCreateFromNeonAuth(result.data.user);
    const jwt = generateToken({
      userId: localUser.id,
      username: localUser.username,
    });

    res.status(201).json({
      message: "User registered via Neon Auth",
      user: {
        id: localUser.id,
        username: localUser.username,
        email: localUser.email,
      },
      neonUser: {
        id: result.data.user.id,
        name: result.data.user.name,
        email: result.data.user.email,
      },
      token: jwt,
      neonToken: result.data.token,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error("Neon Auth signup error:", err);
    res.status(500).json({
      error: "Internal server error",
      timestamp: new Date().toISOString(),
    });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// POST /api/auth/neon/signin
// Body: { email, password }
// ═════════════════════════════════════════════════════════════════════════════

router.post("/neon/signin", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "email and password are required",
        timestamp: new Date().toISOString(),
      });
    }

    // Call Neon Auth sign-in
    const result = await neonAuthRequest(NEON_AUTH_URL + "/sign-in/email", {
      email,
      password,
    });

    if (result.status !== 200 || !result.data.user) {
      const errMsg =
        result.data?.message ||
        result.data?.error ||
        "Invalid credentials (Neon Auth)";
      return res.status(result.status === 200 ? 500 : result.status).json({
        error: errMsg,
        timestamp: new Date().toISOString(),
      });
    }

    // Find/create local user
    const localUser = await findOrCreateFromNeonAuth(result.data.user);
    const jwt = generateToken({
      userId: localUser.id,
      username: localUser.username,
    });

    res.json({
      message: "Login successful via Neon Auth",
      user: {
        id: localUser.id,
        username: localUser.username,
        email: localUser.email,
      },
      neonUser: {
        id: result.data.user.id,
        name: result.data.user.name,
        email: result.data.user.email,
      },
      token: jwt,
      neonToken: result.data.token,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error("Neon Auth signin error:", err);
    res.status(500).json({
      error: "Internal server error",
      timestamp: new Date().toISOString(),
    });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// GET /api/auth/neon/info — Neon Auth config info (public)
// ═════════════════════════════════════════════════════════════════════════════

router.get("/neon/info", (req, res) => {
  res.json({
    neonAuthEnabled: true,
    neonAuthUrl: NEON_AUTH_URL,
    providers: ["email", "google", "github"],
    oauthProviders: {
      google: { enabled: true, type: "shared-keys", endpoint: "/api/auth/neon/oauth/google" },
      github: { enabled: true, endpoint: "/api/auth/neon/oauth/github" },
    },
    note: "Email: POST /api/auth/neon/signup and /signin. OAuth: GET /api/auth/neon/oauth/google or /github",
    timestamp: new Date().toISOString(),
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Neon Auth OAuth — Google & GitHub via Better Auth social sign-in
// ═════════════════════════════════════════════════════════════════════════════

// ─── HTML pages ──────────────────────────────────────────────────────────────

function neonOAuthSuccessHtml(username) {
  return `<!DOCTYPE html>
<html><head><title>Remote – Login Successful</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         display: flex; align-items: center; justify-content: center; height: 100vh;
         margin: 0; background: #1a1a2e; color: #eee; }
  .card { text-align: center; padding: 3rem; background: #16213e; border-radius: 16px;
          box-shadow: 0 8px 32px rgba(0,0,0,0.3); max-width: 420px; }
  h1 { color: #4fc3f7; margin-bottom: 0.5rem; }
  p { opacity: 0.8; }
  .check { font-size: 4rem; margin-bottom: 1rem; color: #4fc3f7; }
</style></head>
<body><div class="card">
  <div class="check">&#10003;</div>
  <h1>Welcome, ${username}!</h1>
  <p>Login successful via Neon Auth. You can close this window and return to the Remote app.</p>
</div></body></html>`;
}

function neonOAuthBridgeHtml(code) {
  const escaped = (s) => s.replace(/'/g, "\\'").replace(/"/g, "&quot;");
  return `<!DOCTYPE html>
<html><head><title>Remote – Completing Sign-In</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         display: flex; align-items: center; justify-content: center; height: 100vh;
         margin: 0; background: #1a1a2e; color: #eee; }
  .card { text-align: center; padding: 3rem; background: #16213e; border-radius: 16px;
          box-shadow: 0 8px 32px rgba(0,0,0,0.3); max-width: 420px; }
  h1 { color: #4fc3f7; margin-bottom: 0.5rem; }
  p { opacity: 0.8; }
  .spinner { font-size: 2rem; animation: spin 1s linear infinite; display: inline-block; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .check { font-size: 4rem; margin-bottom: 1rem; color: #4fc3f7; }
  .error { color: #ff6b6b; }
</style></head>
<body>
<div class="card" id="card">
  <div class="spinner" id="spin">&#9203;</div>
  <h1 id="title">Completing sign-in&hellip;</h1>
  <p id="msg">Please wait while we verify your account</p>
</div>
<script>
(async function() {
  var code = '${escaped(code)}';
  var neonAuthUrl = '${escaped(NEON_AUTH_URL)}';
  var userData = null;

  // Method 1: Try fetching session from Neon Auth via cookies (CORS)
  try {
    var res = await fetch(neonAuthUrl + '/get-session', {
      credentials: 'include',
      headers: { 'Accept': 'application/json' }
    });
    if (res.ok) {
      var data = await res.json();
      if (data && data.user && data.user.id) {
        userData = data.user;
      }
    }
  } catch(e) {
    console.log('CORS session fetch not available:', e.message);
  }

  // Method 2: Fallback — ask our backend to query the neon_auth DB
  if (!userData) {
    try {
      var res2 = await fetch('/api/auth/neon/oauth-latest-user');
      if (res2.ok) {
        var data2 = await res2.json();
        if (data2 && data2.user && data2.user.id) {
          userData = data2.user;
        }
      }
    } catch(e) {
      console.log('Fallback query failed:', e.message);
    }
  }

  if (!userData) {
    throw new Error('Could not retrieve user information. Please try again.');
  }

  // Send user info to our backend to complete the flow
  var completeRes = await fetch('/api/auth/neon/oauth-complete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code: code, neonUser: userData })
  });
  var completeData = await completeRes.json();

  if (completeData.success) {
    document.getElementById('card').innerHTML =
      '<div class="check">&#10003;</div>' +
      '<h1>Welcome, ' + completeData.username + '!</h1>' +
      '<p>Login successful. You can close this window and return to the Remote app.</p>';
  } else {
    throw new Error(completeData.error || 'Failed to complete sign-in');
  }
})().catch(function(err) {
  document.getElementById('spin').style.display = 'none';
  document.getElementById('title').textContent = 'Sign-in Error';
  document.getElementById('title').classList.add('error');
  document.getElementById('msg').textContent = err.message;
});
</script>
</body></html>`;
}

function neonOAuthErrorHtml(message) {
  return `<!DOCTYPE html>
<html><head><title>Remote – OAuth Error</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         display: flex; align-items: center; justify-content: center; height: 100vh;
         margin: 0; background: #1a1a2e; color: #eee; }
  .card { text-align: center; padding: 3rem; background: #16213e; border-radius: 16px;
          box-shadow: 0 8px 32px rgba(0,0,0,0.3); max-width: 420px; }
  h1 { color: #ff6b6b; margin-bottom: 0.5rem; }
  p { opacity: 0.8; }
  .icon { font-size: 4rem; margin-bottom: 1rem; }
</style></head>
<body><div class="card">
  <div class="icon">&#9888;</div>
  <h1>OAuth Error</h1>
  <p>${message}</p>
</div></body></html>`;
}

// ─── GET /neon/oauth/google — Initiate Google OAuth via Neon Auth ────────────

router.get("/neon/oauth/google", async (req, res) => {
  try {
    const code = req.query.session || generateOAuthCode();
    const callbackURL = `${NEON_AUTH_ORIGIN}/api/auth/neon/oauth-callback?code=${code}`;

    const result = await neonAuthSocialRequest(NEON_AUTH_URL + "/sign-in/social", {
      provider: "google",
      callbackURL,
    });

    pendingNeonOAuth.set(code, { status: "pending", expiresAt: Date.now() + 10 * 60 * 1000 });

    if (result.redirect && result.url) {
      return res.redirect(result.url);
    }
    if (!result.redirect && result.data && result.data.url) {
      return res.redirect(result.data.url);
    }

    console.error("Neon Auth social google response:", JSON.stringify(result.data).substring(0, 500));
    res.status(500).send(neonOAuthErrorHtml(
      "Failed to initiate Google OAuth via Neon Auth. The social sign-in endpoint returned an unexpected response."
    ));
  } catch (err) {
    console.error("Neon OAuth google error:", err);
    res.status(500).send(neonOAuthErrorHtml("Internal server error: " + err.message));
  }
});

// ─── GET /neon/oauth/github — Initiate GitHub OAuth via Neon Auth ────────────

router.get("/neon/oauth/github", async (req, res) => {
  try {
    const code = req.query.session || generateOAuthCode();
    const callbackURL = `${NEON_AUTH_ORIGIN}/api/auth/neon/oauth-callback?code=${code}`;

    const result = await neonAuthSocialRequest(NEON_AUTH_URL + "/sign-in/social", {
      provider: "github",
      callbackURL,
    });

    pendingNeonOAuth.set(code, { status: "pending", expiresAt: Date.now() + 10 * 60 * 1000 });

    if (result.redirect && result.url) {
      return res.redirect(result.url);
    }
    if (!result.redirect && result.data && result.data.url) {
      return res.redirect(result.data.url);
    }

    console.error("Neon Auth social github response:", JSON.stringify(result.data).substring(0, 500));
    res.status(500).send(neonOAuthErrorHtml(
      "Failed to initiate GitHub OAuth via Neon Auth. The social sign-in endpoint returned an unexpected response."
    ));
  } catch (err) {
    console.error("Neon OAuth github error:", err);
    res.status(500).send(neonOAuthErrorHtml("Internal server error: " + err.message));
  }
});

// ─── GET /neon/oauth-callback — Bridge page after Neon Auth OAuth ────────────

router.get("/neon/oauth-callback", (req, res) => {
  const { code } = req.query;
  if (!code || !pendingNeonOAuth.has(code)) {
    return res.status(400).send(neonOAuthErrorHtml("Invalid or expired OAuth session. Please try again."));
  }
  res.send(neonOAuthBridgeHtml(code));
});

// ─── GET /neon/oauth-latest-user — Fallback: query neon_auth schema ──────────

router.get("/neon/oauth-latest-user", async (req, res) => {
  try {
    const prisma = getDb();
    const result = await prisma.$queryRawUnsafe(`
      SELECT u.id, u.name, u.email, u."emailVerified", u.image
      FROM neon_auth.session s
      JOIN neon_auth."user" u ON s."userId" = u.id
      WHERE s."createdAt" > NOW() - INTERVAL '2 minutes'
      ORDER BY s."createdAt" DESC
      LIMIT 1
    `);

    if (result && result.length > 0) {
      res.json({ user: result[0], timestamp: new Date().toISOString() });
    } else {
      res.status(404).json({ error: "No recent Neon Auth session found", timestamp: new Date().toISOString() });
    }
  } catch (err) {
    console.error("Error querying neon_auth schema:", err);
    res.status(500).json({ error: "Failed to query neon_auth database", timestamp: new Date().toISOString() });
  }
});

// ─── POST /neon/oauth-complete — Receives user info from bridge page ─────────

router.post("/neon/oauth-complete", async (req, res) => {
  try {
    const { code, neonUser } = req.body;
    if (!code || !pendingNeonOAuth.has(code)) {
      return res.status(400).json({ error: "Invalid or expired session", timestamp: new Date().toISOString() });
    }
    if (!neonUser || !neonUser.id) {
      return res.status(400).json({ error: "Invalid user data", timestamp: new Date().toISOString() });
    }

    // Verify user exists in neon_auth schema for security
    try {
      const prisma = getDb();
      const verified = await prisma.$queryRawUnsafe(
        `SELECT id, email FROM neon_auth."user" WHERE id = $1 LIMIT 1`,
        neonUser.id
      );
      if (!verified || verified.length === 0) {
        return res.status(400).json({ error: "User not found in Neon Auth", timestamp: new Date().toISOString() });
      }
    } catch (dbErr) {
      console.warn("Could not verify neon_auth user (non-fatal):", dbErr.message);
      // Continue anyway — the user data came from our bridge page
    }

    const localUser = await findOrCreateFromNeonAuth(neonUser);
    const jwt = generateToken({ userId: localUser.id, username: localUser.username });

    pendingNeonOAuth.set(code, {
      status: "complete",
      token: jwt,
      user: { id: localUser.id, username: localUser.username, email: localUser.email },
      expiresAt: Date.now() + 5 * 60 * 1000,
    });

    res.json({ success: true, username: localUser.username, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error("Neon OAuth complete error:", err);
    res.status(500).json({ error: "Internal server error", timestamp: new Date().toISOString() });
  }
});

// ─── GET /neon/oauth-result/:code — Desktop polls for JWT ────────────────────

router.get("/neon/oauth-result/:code", (req, res) => {
  const entry = pendingNeonOAuth.get(req.params.code);
  if (!entry || entry.status === "pending") {
    return res.status(202).json({ status: "pending", timestamp: new Date().toISOString() });
  }
  // One-time use
  pendingNeonOAuth.delete(req.params.code);
  res.json({ status: "ok", token: entry.token, user: entry.user, timestamp: new Date().toISOString() });
});

module.exports = router;
