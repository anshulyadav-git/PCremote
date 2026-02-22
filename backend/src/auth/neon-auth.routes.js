/**
 * Neon Auth routes — sign-up/sign-in via Neon's managed auth (Better Auth)
 *
 * Flow: Desktop/client → our backend → Neon Auth API → create/link local user → return our JWT
 */

const express = require("express");
const https = require("https");
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
    providers: ["email"],
    note: "Sign up/in via POST /api/auth/neon/signup and /api/auth/neon/signin",
    timestamp: new Date().toISOString(),
  });
});

module.exports = router;
