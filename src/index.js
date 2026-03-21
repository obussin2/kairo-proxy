import "dotenv/config";
import { createServer } from "node:http";
import { fileURLToPath } from "url";
import { join, dirname } from "path";
import { readFileSync } from "fs";
import express from "express";
import session from "express-session";
import connectMongo from "connect-mongo";
import mongoose, { Schema } from "mongoose";
import bcrypt from "bcryptjs";
import wisp from "wisp-server-node";
import { uvPath } from "@titaniumnetwork-dev/ultraviolet";
import { epoxyPath } from "@mercuryworkshop/epoxy-transport";
import { baremuxPath } from "@mercuryworkshop/bare-mux/node";

const __dirname = dirname(fileURLToPath(import.meta.url));
const publicPath = join(__dirname, "../public");

// ── Models ───────────────────────────────────────────────
const User = mongoose.model("User", new Schema({
  username:     { type: String, unique: true },
  password:     String,
  displayName:  { type: String, default: "" },
  proxyCookies: { type: String, default: "" },
  createdAt:    { type: Date, default: Date.now }
}));

const Bookmarklet = mongoose.model("Bookmarklet", new Schema({
  name:        { type: String, required: true },
  description: { type: String, default: "" },
  code:        { type: String, required: true },
  createdAt:   { type: Date, default: Date.now }
}));

// ── Connect ──────────────────────────────────────────────
await mongoose.connect(process.env.MONGO_URI, { maxPoolSize: 10 });
console.log("MongoDB connected");

if (!(await User.findOne({ username: "admin" }))) {
  const hash = await bcrypt.hash("stu8976@admin", 10);
  await User.create({ username: "admin", password: hash, displayName: "Osazee" });
  console.log("Admin seeded");
}

// ── Express ──────────────────────────────────────────────
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || "kairo-secret",
  resave: false,
  saveUninitialized: false,
  store: connectMongo.create({ mongoUrl: process.env.MONGO_URI }),
  cookie: { secure: false, maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// Auth helpers
const loggedIn  = (req) => !!req.session?.username;
const adminOnly = (req) => !!req.session?.isAdmin;

// ── Page routes ──────────────────────────────────────────
app.get("/", (req, res) => {
  if (!loggedIn(req)) return res.redirect("/login.html");
  res.sendFile(join(publicPath, "index.html"));
});

app.get("/admin", (req, res) => {
  if (!adminOnly(req)) return res.redirect("/login.html");
  res.sendFile(join(publicPath, "admin.html"));
});

// ── API ──────────────────────────────────────────────────
let pinsCache = null;
app.get("/api/pins", (req, res) => {
  if (!loggedIn(req)) return res.status(401).json({ error: "Unauthorized" });
  if (!pinsCache) pinsCache = JSON.parse(readFileSync(join(__dirname, "../config.json"), "utf8"));
  res.set("Cache-Control", "public, max-age=60");
  res.json({ pins: pinsCache.pins });
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.json({ success: false, error: "Missing fields" });
  const user = await User.findOne({ username });
  if (!user) return res.json({ success: false, error: "Invalid credentials" });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.json({ success: false, error: "Invalid credentials" });
  req.session.username = username;
  req.session.isAdmin = username === "admin";
  req.session.displayName = user.displayName || username;
  // Save session before responding so redirect works
  req.session.save(() => {
    res.json({ success: true, isAdmin: req.session.isAdmin, displayName: req.session.displayName });
  });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

app.get("/api/me", (req, res) => {
  if (!req.session?.username) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, username: req.session.username, displayName: req.session.displayName || req.session.username, isAdmin: !!req.session.isAdmin });
});

app.get("/api/users", async (req, res) => {
  if (!adminOnly(req)) return res.status(401).json({ error: "Unauthorized" });
  res.json(await User.find({}, { password: 0, proxyCookies: 0 }));
});

app.post("/api/users", async (req, res) => {
  if (!adminOnly(req)) return res.status(401).json({ error: "Unauthorized" });
  const { username, password, displayName } = req.body;
  if (!username || !password) return res.json({ success: false, error: "Missing fields" });
  try {
    const hash = await bcrypt.hash(password, 10);
    await User.create({ username, password: hash, displayName: displayName || username });
    res.json({ success: true });
  } catch { res.json({ success: false, error: "Username already exists" }); }
});

app.delete("/api/users/:username", async (req, res) => {
  if (!adminOnly(req)) return res.status(401).json({ error: "Unauthorized" });
  if (req.params.username === "admin") return res.json({ success: false, error: "Cannot delete admin" });
  await User.deleteOne({ username: req.params.username });
  res.json({ success: true });
});

app.get("/api/cookies", async (req, res) => {
  if (!loggedIn(req)) return res.status(401).json({ error: "Unauthorized" });
  const user = await User.findOne({ username: req.session.username }, { proxyCookies: 1 });
  res.json({ cookies: user?.proxyCookies || "" });
});

app.post("/api/cookies", async (req, res) => {
  if (!loggedIn(req)) return res.status(401).json({ error: "Unauthorized" });
  const { cookies } = req.body;
  if (typeof cookies !== "string") return res.json({ success: false });
  await User.updateOne({ username: req.session.username }, { $set: { proxyCookies: cookies.slice(0, 65536) } });
  res.json({ success: true });
});

app.delete("/api/cookies", async (req, res) => {
  if (!loggedIn(req)) return res.status(401).json({ error: "Unauthorized" });
  await User.updateOne({ username: req.session.username }, { $set: { proxyCookies: "" } });
  res.json({ success: true });
});

app.get("/api/bookmarklets", async (req, res) => {
  if (!loggedIn(req)) return res.status(401).json({ error: "Unauthorized" });
  res.json(await Bookmarklet.find({}).sort({ createdAt: -1 }));
});

app.post("/api/bookmarklets", async (req, res) => {
  if (!adminOnly(req)) return res.status(401).json({ error: "Unauthorized" });
  const { name, description, code } = req.body;
  if (!name || !code) return res.json({ success: false, error: "Name and code required" });
  try {
    const bm = await Bookmarklet.create({ name, description: description || "", code });
    res.json({ success: true, bookmarklet: bm });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.delete("/api/bookmarklets/:id", async (req, res) => {
  if (!adminOnly(req)) return res.status(401).json({ error: "Unauthorized" });
  await Bookmarklet.deleteOne({ _id: req.params.id });
  res.json({ success: true });
});

// ── Static files — public FIRST so it wins over /uv/ ────
app.use(express.static(publicPath));
app.use("/uv/", express.static(uvPath));
app.use("/epoxy/", express.static(epoxyPath));
app.use("/baremux/", express.static(baremuxPath));

// UV service paths — return empty page so SW can take over
app.get("/uv/service/*", (req, res) => {
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  res.send("<!DOCTYPE html><html><head></head><body></body></html>");
});

app.use((req, res) => {
  res.status(404).sendFile(join(publicPath, "404.html"));
});

// ── HTTP server ──────────────────────────────────────────
const server = createServer();
server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;

server.on("request", (req, res) => {
  // No COOP/COEP needed for UV — removing them fixes external images like Simple Icons
  app(req, res);
});

server.on("upgrade", (req, socket, head) => {
  if (req.url.endsWith("/wisp/")) {
    socket.setNoDelay(true);
    wisp.routeRequest(req, socket, head);
  } else {
    socket.end();
  }
});

const PORT = parseInt(process.env.PORT || "3000");
server.listen(PORT, () => console.log(`Kairo listening on port ${PORT}`));
