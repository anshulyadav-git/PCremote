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
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    name: "remote-backend",
    version: "1.0.0",
    runtime: "vercel-serverless",
    db: "prisma-neon-postgres",
  });
});

app.use("/api/auth", authLimiter, authRoutes);
app.use("/api/auth", oauthRoutes);
app.use("/api/devices", deviceRoutes);

module.exports = app;
