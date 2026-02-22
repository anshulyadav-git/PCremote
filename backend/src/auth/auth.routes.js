const express = require("express");
const bcrypt = require("bcryptjs");
const { getDb } = require("../db/database");
const { generateToken } = require("./middleware");

const router = express.Router();

/**
 * POST /api/auth/register
 * Body: { username, email, password }
 */
router.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: "username, email, and password are required", timestamp: new Date().toISOString() });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters", timestamp: new Date().toISOString() });
    }

    const prisma = getDb();

    const existing = await prisma.user.findFirst({
      where: { OR: [{ username }, { email }] },
    });
    if (existing) {
      return res.status(409).json({ error: "Username or email already exists", timestamp: new Date().toISOString() });
    }

    const hash = await bcrypt.hash(password, 12);
    const user = await prisma.user.create({
      data: { username, email, password: hash },
    });

    const token = generateToken({ userId: user.id, username });

    res.status(201).json({
      message: "User registered successfully",
      user: { id: user.id, username, email },
      token,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: "Internal server error", timestamp: new Date().toISOString() });
  }
});

/**
 * POST /api/auth/login
 * Body: { username, password }
 */
router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "username and password are required", timestamp: new Date().toISOString() });
    }

    const prisma = getDb();
    const user = await prisma.user.findFirst({
      where: { OR: [{ username }, { email: username }] },
    });

    if (!user) {
      return res.status(401).json({ error: "Invalid credentials", timestamp: new Date().toISOString() });
    }

    if (!user.password) {
      return res.status(401).json({ error: "This account uses OAuth. Sign in with Google or GitHub.", timestamp: new Date().toISOString() });
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(401).json({ error: "Invalid credentials", timestamp: new Date().toISOString() });
    }

    const token = generateToken({ userId: user.id, username: user.username });

    res.json({
      message: "Login successful",
      user: { id: user.id, username: user.username, email: user.email },
      token,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Internal server error", timestamp: new Date().toISOString() });
  }
});

/**
 * GET /api/auth/me — get current user info (requires auth)
 */
router.get("/me", require("./middleware").authMiddleware, async (req, res) => {
  const prisma = getDb();
  const user = await prisma.user.findUnique({
    where: { id: req.user.userId },
    select: { id: true, username: true, email: true, createdAt: true },
  });
  if (!user) return res.status(404).json({ error: "User not found", timestamp: new Date().toISOString() });
  res.json({ user, timestamp: new Date().toISOString() });
});

module.exports = router;
