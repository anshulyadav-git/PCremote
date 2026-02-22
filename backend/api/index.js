require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const authRoutes = require("../src/auth/auth.routes");
const oauthRoutes = require("../src/auth/oauth.routes");
const deviceRoutes = require("../src/routes/devices");
const { initDb } = require("../src/db/database");

const app = express();

// --- DB init on cold start ---
let dbInitialized = false;
app.use(async (req, res, next) => {
  if (!dbInitialized) {
    try {
      await initDb();
      dbInitialized = true;
    } catch (err) {
      console.error("DB init error:", err);
    }
  }
  next();
});

// --- Middleware ---
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: "10mb" }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: "Too many requests, try again later" },
});

// --- Routes ---

// Root — full API documentation
app.get("/api", (req, res) => {
  res.json({
    name: "PCremote Backend API",
    version: "1.0.0",
    description: "Backend API for the PCremote app — remote device control, authentication, and device pairing.",
    runtime: "vercel-serverless",
    database: "prisma-neon-postgres",
    baseUrl: "https://pcremote-backend-ashen.vercel.app/api",
    documentation: {
      health: {
        "GET /api/health": {
          description: "Check API and database health status",
          auth: false,
          response: {
            status: "ok",
            name: "remote-backend",
            version: "1.0.0",
            runtime: "vercel-serverless",
            db: "prisma-neon-postgres",
          },
        },
      },
      auth: {
        "POST /api/auth/register": {
          description: "Register a new user account",
          auth: false,
          rateLimit: "20 requests per 15 minutes",
          body: {
            username: "string (required)",
            email: "string (required)",
            password: "string (required, min 6 chars)",
          },
          responses: {
            201: { message: "User registered successfully", user: { id: "number", username: "string", email: "string" }, token: "JWT string" },
            400: { error: "username, email, and password are required" },
            409: { error: "Username or email already exists" },
            500: { error: "Internal server error" },
          },
        },
        "POST /api/auth/login": {
          description: "Login with username/email and password",
          auth: false,
          rateLimit: "20 requests per 15 minutes",
          body: {
            username: "string (required — username or email)",
            password: "string (required)",
          },
          responses: {
            200: { message: "Login successful", user: { id: "number", username: "string", email: "string" }, token: "JWT string" },
            401: { error: "Invalid credentials" },
            500: { error: "Internal server error" },
          },
        },
        "GET /api/auth/me": {
          description: "Get current authenticated user info",
          auth: "Bearer <JWT token>",
          responses: {
            200: { user: { id: "number", username: "string", email: "string", createdAt: "ISO date" } },
            401: { error: "No token provided | Invalid or expired token" },
            404: { error: "User not found" },
          },
        },
      },
      oauth: {
        "GET /api/auth/google": {
          description: "Initiate Google OAuth sign-in (redirects to Google)",
          auth: false,
          queryParams: { session: "string (optional — session ID for desktop polling)" },
          response: "302 redirect to Google OAuth consent screen",
        },
        "GET /api/auth/google/callback": {
          description: "Google OAuth callback (handles code exchange)",
          auth: false,
          response: "HTML success page or error message",
        },
        "GET /api/auth/github": {
          description: "Initiate GitHub OAuth sign-in (redirects to GitHub)",
          auth: false,
          queryParams: { session: "string (optional — session ID for desktop polling)" },
          response: "302 redirect to GitHub OAuth authorization",
        },
        "GET /api/auth/github/callback": {
          description: "GitHub OAuth callback (handles code exchange)",
          auth: false,
          response: "HTML success page or error message",
        },
        "GET /api/auth/oauth-result/:sessionId": {
          description: "Poll for OAuth result (used by desktop app after OAuth flow)",
          auth: false,
          params: { sessionId: "string (the session ID passed to /google or /github)" },
          responses: {
            200: { status: "ok", token: "JWT string", user: { id: "number", username: "string", email: "string" } },
            202: { status: "pending" },
          },
        },
      },
      devices: {
        "GET /api/devices": {
          description: "List all devices for the authenticated user",
          auth: "Bearer <JWT token>",
          responses: {
            200: { devices: [{ id: "string", name: "string", type: "string", platform: "string", lastSeen: "ISO date", isOnline: "boolean", is_online: "boolean (live WebSocket status)", createdAt: "ISO date" }] },
            401: { error: "No token provided | Invalid or expired token" },
          },
        },
        "DELETE /api/devices/:id": {
          description: "Remove a device and all its pairings",
          auth: "Bearer <JWT token>",
          params: { id: "string (device ID)" },
          responses: {
            200: { message: "Device removed" },
            404: { error: "Device not found" },
          },
        },
        "GET /api/devices/:id/pairs": {
          description: "List all device pairs for a specific device",
          auth: "Bearer <JWT token>",
          params: { id: "string (device ID)" },
          responses: {
            200: { pairs: [{ id: "number", deviceA: "string", deviceB: "string", status: "string", paired_device_id: "string", paired_device: { id: "string", name: "string", type: "string", platform: "string" }, paired_online: "boolean" }] },
            404: { error: "Device not found" },
          },
        },
        "POST /api/devices/:id/unpair/:targetId": {
          description: "Unpair two devices",
          auth: "Bearer <JWT token>",
          params: { id: "string (device ID)", targetId: "string (target device ID)" },
          responses: {
            200: { message: "Devices unpaired" },
            404: { error: "Pair not found" },
          },
        },
      },
      websocket: {
        "WSS /api (upgrade)": {
          description: "WebSocket connection for real-time device communication",
          auth: "Send auth message after connecting: { type: 'auth', token: 'JWT', deviceId: '...', deviceName: '...', deviceType: '...', platform: '...' }",
          messageTypes: {
            auth: "Authenticate and register device",
            command: "Send command to a paired device",
            pair_request: "Request to pair with another device",
            pair_response: "Accept or reject a pair request",
            device_list: "Request list of online devices",
          },
        },
      },
    },
    authentication: {
      type: "Bearer Token (JWT)",
      header: "Authorization: Bearer <token>",
      expiresIn: "7 days",
      obtain: "POST /api/auth/register, POST /api/auth/login, or OAuth flow",
    },
    rateLimit: {
      auth: "20 requests per 15 minutes on /api/auth/*",
    },
    timestamp: new Date().toISOString(),
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    name: "remote-backend",
    version: "1.0.0",
    runtime: "vercel-serverless",
    db: "prisma-neon-postgres",
    timestamp: new Date().toISOString(),
  });
});

app.use("/api/auth", authLimiter, authRoutes);
app.use("/api/auth", oauthRoutes);
app.use("/api/devices", deviceRoutes);

// --- 404 catch-all ---
app.use("/api/*", (req, res) => {
  res.status(404).json({
    error: "Not found",
    message: `No endpoint matches ${req.method} ${req.originalUrl}`,
    hint: "Visit GET /api for full API documentation",
  });
});

module.exports = app;
