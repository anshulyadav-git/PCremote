const express = require("express");
const https = require("https");
const { v4: uuidv4 } = require("uuid");
const { getDb } = require("../db/database");
const { generateToken } = require("./middleware");

const router = express.Router();

// Temp store: sessionId → { token, user, expiresAt }
const pendingOAuth = new Map();

// Cleanup expired sessions every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of pendingOAuth) {
    if (val.expiresAt < now) pendingOAuth.delete(key);
  }
}, 5 * 60 * 1000);

// ─── Helper: HTTPS JSON request ──────────────────────────────────────────────

function httpsRequest(url, options = {}) {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(url);
    const reqOptions = {
      hostname: parsedUrl.hostname,
      path: parsedUrl.pathname + parsedUrl.search,
      method: options.method || "GET",
      headers: {
        Accept: "application/json",
        "User-Agent": "Remote-Backend/1.0",
        ...options.headers,
      },
    };

    const req = https.request(reqOptions, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          resolve(JSON.parse(data));
        } catch {
          resolve(data);
        }
      });
    });
    req.on("error", reject);
    if (options.body) req.write(options.body);
    req.end();
  });
}

// ─── Find or create OAuth user ───────────────────────────────────────────────

async function findOrCreateOAuthUser(provider, oauthId, username, email) {
  const prisma = getDb();

  // Check if OAuth user already exists
  const existing = await prisma.user.findFirst({
    where: { oauthProvider: provider, oauthId: oauthId },
  });
  if (existing) return existing;

  // Check if email matches an existing user → link accounts
  if (email) {
    const byEmail = await prisma.user.findUnique({ where: { email } });
    if (byEmail) {
      const updated = await prisma.user.update({
        where: { id: byEmail.id },
        data: { oauthProvider: provider, oauthId: oauthId },
      });
      return updated;
    }
  }

  // Create new user with unique username
  const safeName = username || `${provider}_${oauthId.slice(0, 8)}`;
  let finalName = safeName;
  let counter = 1;
  while (true) {
    const dup = await prisma.user.findUnique({ where: { username: finalName } });
    if (!dup) break;
    finalName = `${safeName}_${counter++}`;
  }

  const finalEmail = email || `${finalName}@oauth.local`;
  const result = await prisma.user.create({
    data: {
      username: finalName,
      email: finalEmail,
      password: "",
      oauthProvider: provider,
      oauthId: oauthId,
    },
  });
  return result;
}

// ─── Success HTML page ───────────────────────────────────────────────────────

function successHtml(username) {
  return `<!DOCTYPE html>
<html><head><title>Remote – Login Successful</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         display: flex; align-items: center; justify-content: center; height: 100vh;
         margin: 0; background: #1a1a2e; color: #eee; }
  .card { text-align: center; padding: 3rem; background: #16213e; border-radius: 16px;
          box-shadow: 0 8px 32px rgba(0,0,0,0.3); }
  h1 { color: #4fc3f7; margin-bottom: 0.5rem; }
  p { opacity: 0.8; }
  .check { font-size: 4rem; margin-bottom: 1rem; }
</style></head>
<body><div class="card">
  <div class="check">&#10003;</div>
  <h1>Welcome, ${username}!</h1>
  <p>Login successful. You can close this window and return to the Remote app.</p>
</div></body></html>`;
}

// ═════════════════════════════════════════════════════════════════════════════
// GOOGLE OAuth
// ═════════════════════════════════════════════════════════════════════════════

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "";
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || "http://localhost:3000/api/auth/google/callback";

router.get("/google", (req, res) => {
  const sessionId = req.query.session || uuidv4();
  const scope = encodeURIComponent("openid email profile");
  const state = sessionId;
  const url =
    `https://accounts.google.com/o/oauth2/v2/auth` +
    `?client_id=${GOOGLE_CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(GOOGLE_REDIRECT_URI)}` +
    `&response_type=code` +
    `&scope=${scope}` +
    `&state=${state}` +
    `&access_type=offline` +
    `&prompt=consent`;
  res.redirect(url);
});

router.get("/google/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code) return res.status(400).send("Missing code");

    // Exchange code for tokens
    const body = new URLSearchParams({
      code,
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      redirect_uri: GOOGLE_REDIRECT_URI,
      grant_type: "authorization_code",
    }).toString();

    const tokenData = await httpsRequest("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });

    if (!tokenData.access_token) {
      console.error("Google token error:", tokenData);
      return res.status(400).send("Failed to get token from Google");
    }

    // Fetch user profile
    const profile = await httpsRequest(
      `https://www.googleapis.com/oauth2/v2/userinfo?access_token=${tokenData.access_token}`
    );

    const user = await findOrCreateOAuthUser("google", profile.id, profile.name, profile.email);
    const jwt = generateToken({ userId: user.id, username: user.username });

    // Store for desktop app polling
    if (state) {
      pendingOAuth.set(state, {
        token: jwt,
        user: { id: user.id, username: user.username, email: user.email },
        expiresAt: Date.now() + 5 * 60 * 1000,
      });
    }

    res.send(successHtml(user.username));
  } catch (err) {
    console.error("Google OAuth error:", err);
    res.status(500).send("OAuth error: " + err.message);
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// GITHUB OAuth
// ═════════════════════════════════════════════════════════════════════════════

const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID || "";
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET || "";
const GITHUB_REDIRECT_URI = process.env.GITHUB_REDIRECT_URI || "http://localhost:3000/api/auth/github/callback";

router.get("/github", (req, res) => {
  const sessionId = req.query.session || uuidv4();
  const state = sessionId;
  const url =
    `https://github.com/login/oauth/authorize` +
    `?client_id=${GITHUB_CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(GITHUB_REDIRECT_URI)}` +
    `&scope=user:email` +
    `&state=${state}`;
  res.redirect(url);
});

router.get("/github/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code) return res.status(400).send("Missing code");

    // Exchange code for access token
    const body = JSON.stringify({
      client_id: GITHUB_CLIENT_ID,
      client_secret: GITHUB_CLIENT_SECRET,
      code,
      redirect_uri: GITHUB_REDIRECT_URI,
    });

    const tokenData = await httpsRequest("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body,
    });

    if (!tokenData.access_token) {
      console.error("GitHub token error:", tokenData);
      return res.status(400).send("Failed to get token from GitHub");
    }

    // Fetch user profile
    const profile = await httpsRequest("https://api.github.com/user", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });

    // Fetch email if not public
    let email = profile.email;
    if (!email) {
      const emails = await httpsRequest("https://api.github.com/user/emails", {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
      });
      if (Array.isArray(emails)) {
        const primary = emails.find((e) => e.primary) || emails[0];
        if (primary) email = primary.email;
      }
    }

    const user = await findOrCreateOAuthUser("github", String(profile.id), profile.login, email);
    const jwt = generateToken({ userId: user.id, username: user.username });

    // Store for desktop app polling
    if (state) {
      pendingOAuth.set(state, {
        token: jwt,
        user: { id: user.id, username: user.username, email: user.email },
        expiresAt: Date.now() + 5 * 60 * 1000,
      });
    }

    res.send(successHtml(user.username));
  } catch (err) {
    console.error("GitHub OAuth error:", err);
    res.status(500).send("OAuth error: " + err.message);
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// Poll endpoint — desktop app calls this to retrieve the JWT after OAuth
// ═════════════════════════════════════════════════════════════════════════════

router.get("/oauth-result/:sessionId", (req, res) => {
  const entry = pendingOAuth.get(req.params.sessionId);
  if (!entry) {
    return res.status(202).json({ status: "pending" });
  }
  // One-time use — delete after retrieval
  pendingOAuth.delete(req.params.sessionId);
  res.json({ status: "ok", token: entry.token, user: entry.user });
});

module.exports = router;
