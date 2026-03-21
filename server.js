require("dotenv").config();
const cluster = require("cluster");
const os = require("os");

if (cluster.isMaster || cluster.isPrimary) {
  const numCPUs = os.cpus().length;
  console.log(`Master ${process.pid} — forking ${numCPUs} workers`);
  for (let i = 0; i < numCPUs; i++) cluster.fork();
  cluster.on("exit", (worker) => {
    console.log(`Worker ${worker.process.pid} died — restarting`);
    cluster.fork();
  });
  return;
}

const express = require("express");
const { createServer } = require("http");
const { server: wisp } = require("@mercuryworkshop/wisp-js/server");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const compression = require("compression");
const path = require("path");
const fs = require("fs");

const app = express();
const server = createServer(app);

server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;

console.log(`Worker ${process.pid} started`);

// ── MongoDB ──────────────────────────────────────────────
mongoose.connect(process.env.MONGO_URI, {
  maxPoolSize: 10,
  serverSelectionTimeoutMS: 5000,
}).then(async () => {
  console.log(`Worker ${process.pid} — MongoDB connected`);
  await seedAdmin();
}).catch(err => console.error("MongoDB error:", err));

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
  displayName: { type: String, default: "" },
  createdAt: { type: Date, default: Date.now },
  proxyCookies: { type: String, default: "" }
});
const User = mongoose.model("User", userSchema);

const bookmarkletSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, default: "" },
  code: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});
const Bookmarklet = mongoose.model("Bookmarklet", bookmarkletSchema);

async function seedAdmin() {
  const existing = await User.findOne({ username: "admin" });
  if (!existing) {
    const hash = await bcrypt.hash("stu8976@admin", 10);
    await User.create({ username: "admin", password: hash, displayName: "Osazee" });
    console.log("Admin user created");
  }
}

// ── Middleware ───────────────────────────────────────────
app.use(compression({ level: 6, threshold: 1024 }));
app.use(express.json({ limit: "256kb" }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || "kairo-secret",
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// ── Scramjet static — try multiple path strategies ───────
function findScramjetDist() {
  const candidates = [
    path.join(path.dirname(require.resolve("@mercuryworkshop/scramjet")), "../dist"),
    path.join(__dirname, "node_modules/@mercuryworkshop/scramjet/dist"),
    path.join(process.cwd(), "node_modules/@mercuryworkshop/scramjet/dist"),
  ];
  for (const p of candidates) {
    try {
      if (fs.existsSync(p) && fs.existsSync(path.join(p, "scramjet.bundle.js"))) {
        console.log(`Scramjet dist found at: ${p}`);
        return p;
      }
    } catch(e) {}
  }
  console.warn("Scramjet dist not found — proxy navigation will not work");
  return null;
}

const scramjetDist = findScramjetDist();
if (scramjetDist) {
  app.use("/scramjet/", express.static(scramjetDist, {
    maxAge: "7d", immutable: true, etag: true,
  }));
}

app.use(express.static(path.join(__dirname, "public"), {
  maxAge: "1m", etag: true,
}));

// ── Auth helpers ─────────────────────────────────────────
function requireLogin(req, res, next) {
  if (req.session && req.session.username) return next();
  if (req.path.startsWith("/api/")) return res.status(401).json({ error: "Unauthorized" });
  res.redirect("/login.html");
}

function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) return next();
  res.status(401).json({ error: "Unauthorized" });
}

// ── Routes ───────────────────────────────────────────────
app.get("/", requireLogin, (req, res) =>
  res.sendFile(path.join(__dirname, "public", "index.html")));

app.get("/admin", (req, res) => {
  if (!req.session || !req.session.isAdmin) return res.redirect("/login.html");
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

let pinsCache = null;
app.get("/api/pins", requireLogin, (req, res) => {
  if (!pinsCache) pinsCache = JSON.parse(fs.readFileSync(path.join(__dirname, "config.json")));
  res.set("Cache-Control", "public, max-age=60");
  res.json({ pins: pinsCache.pins });
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.json({ success: false, error: "Invalid credentials" });
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.json({ success: false, error: "Invalid credentials" });
  req.session.isAdmin = username === "admin";
  req.session.username = username;
  req.session.displayName = user.displayName || username;
  res.json({ success: true, isAdmin: req.session.isAdmin, displayName: req.session.displayName });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get("/api/me", (req, res) => {
  if (!req.session.username) return res.json({ loggedIn: false });
  res.json({
    loggedIn: true,
    username: req.session.username,
    displayName: req.session.displayName || req.session.username,
    isAdmin: !!req.session.isAdmin
  });
});

// ── Cookie sync ──────────────────────────────────────────
app.get("/api/cookies", requireLogin, async (req, res) => {
  const user = await User.findOne({ username: req.session.username }, { proxyCookies: 1 });
  res.json({ cookies: user?.proxyCookies || "" });
});

app.post("/api/cookies", requireLogin, async (req, res) => {
  const { cookies } = req.body;
  if (typeof cookies !== "string") return res.json({ success: false });
  await User.updateOne({ username: req.session.username }, { $set: { proxyCookies: cookies.slice(0, 65536) } });
  res.json({ success: true });
});

app.delete("/api/cookies", requireLogin, async (req, res) => {
  await User.updateOne({ username: req.session.username }, { $set: { proxyCookies: "" } });
  res.json({ success: true });
});

// ── User management ──────────────────────────────────────
app.get("/api/users", requireAdmin, async (req, res) => {
  const users = await User.find({}, { password: 0, proxyCookies: 0 });
  res.json(users);
});

app.post("/api/users", requireAdmin, async (req, res) => {
  const { username, password, displayName } = req.body;
  if (!username || !password) return res.json({ success: false, error: "Missing fields" });
  try {
    const hash = await bcrypt.hash(password, 10);
    await User.create({ username, password: hash, displayName: displayName || username });
    res.json({ success: true });
  } catch (e) {
    res.json({ success: false, error: "Username already exists" });
  }
});

app.delete("/api/users/:username", requireAdmin, async (req, res) => {
  if (req.params.username === "admin") return res.json({ success: false, error: "Cannot delete admin" });
  await User.deleteOne({ username: req.params.username });
  res.json({ success: true });
});

// ── Bookmarklets ─────────────────────────────────────────
app.get("/api/bookmarklets", requireLogin, async (req, res) => {
  const bookmarklets = await Bookmarklet.find({}).sort({ createdAt: -1 });
  res.json(bookmarklets);
});

app.post("/api/bookmarklets", requireAdmin, async (req, res) => {
  const { name, description, code } = req.body;
  if (!name || !code) return res.json({ success: false, error: "Name and code required" });
  try {
    const bm = await Bookmarklet.create({ name, description: description || "", code });
    res.json({ success: true, bookmarklet: bm });
  } catch (e) {
    res.json({ success: false, error: e.message });
  }
});

app.delete("/api/bookmarklets/:id", requireAdmin, async (req, res) => {
  await Bookmarklet.deleteOne({ _id: req.params.id });
  res.json({ success: true });
});

// ── Wisp ─────────────────────────────────────────────────
server.on("upgrade", (req, socket, head) => {
  socket.setNoDelay(true);
  wisp.routeRequest(req, socket, head);
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Worker ${process.pid} listening on port ${PORT}`));
