const express = require("express");
const { getDb } = require("../db/database");
const { authMiddleware } = require("../auth/middleware");
const { clients } = require("../ws/wsHandler");

const router = express.Router();

// All device routes require auth
router.use(authMiddleware);

/**
 * GET /api/devices — list user's devices
 */
router.get("/", async (req, res) => {
  const prisma = getDb();
  const devices = await prisma.device.findMany({
    where: { userId: req.user.userId },
    orderBy: { lastSeen: "desc" },
    select: { id: true, name: true, type: true, platform: true, lastSeen: true, isOnline: true, createdAt: true },
  });

  const enriched = devices.map((d) => ({
    ...d,
    is_online: clients.has(d.id) ? true : false,
  }));

  res.json({ devices: enriched, timestamp: new Date().toISOString() });
});

/**
 * DELETE /api/devices/:id — remove a device
 */
router.delete("/:id", async (req, res) => {
  const prisma = getDb();
  const device = await prisma.device.findFirst({
    where: { id: req.params.id, userId: req.user.userId },
  });

  if (!device) {
    return res.status(404).json({ error: "Device not found", timestamp: new Date().toISOString() });
  }

  await prisma.devicePair.deleteMany({
    where: { OR: [{ deviceA: req.params.id }, { deviceB: req.params.id }] },
  });
  await prisma.device.delete({ where: { id: req.params.id } });

  res.json({ message: "Device removed", timestamp: new Date().toISOString() });
});

/**
 * GET /api/devices/:id/pairs — list device pairs
 */
router.get("/:id/pairs", async (req, res) => {
  const prisma = getDb();
  const device = await prisma.device.findFirst({
    where: { id: req.params.id, userId: req.user.userId },
  });

  if (!device) {
    return res.status(404).json({ error: "Device not found", timestamp: new Date().toISOString() });
  }

  const pairs = await prisma.devicePair.findMany({
    where: { OR: [{ deviceA: req.params.id }, { deviceB: req.params.id }] },
  });

  const enriched = [];
  for (const p of pairs) {
    const pairedDeviceId = p.deviceA === req.params.id ? p.deviceB : p.deviceA;
    const pairedDevice = await prisma.device.findUnique({
      where: { id: pairedDeviceId },
      select: { id: true, name: true, type: true, platform: true },
    });
    enriched.push({
      ...p,
      paired_device_id: pairedDeviceId,
      paired_device: pairedDevice || null,
      paired_online: clients.has(pairedDeviceId),
    });
  }

  res.json({ pairs: enriched, timestamp: new Date().toISOString() });
});

/**
 * POST /api/devices/:id/unpair/:targetId — unpair two devices
 */
router.post("/:id/unpair/:targetId", async (req, res) => {
  const prisma = getDb();
  const deleted = await prisma.devicePair.deleteMany({
    where: {
      OR: [
        { deviceA: req.params.id, deviceB: req.params.targetId },
        { deviceA: req.params.targetId, deviceB: req.params.id },
      ],
    },
  });

  if (deleted.count === 0) {
    return res.status(404).json({ error: "Pair not found", timestamp: new Date().toISOString() });
  }

  res.json({ message: "Devices unpaired", timestamp: new Date().toISOString() });
});

module.exports = router;
