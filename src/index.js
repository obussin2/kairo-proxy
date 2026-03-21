import "dotenv/config";
import { createServer } from "node:http";
import { fileURLToPath } from "url";
import { join, dirname } from "path";
import { readFileSync } from "fs";
import { server as wisp, logging } from "@mercuryworkshop/wisp-js/server";
import Fastify from "fastify";
import fastifyStatic from "@fastify/static";
import { scramjetPath } from "@mercuryworkshop/scramjet/path";
import { libcurlPath } from "@mercuryworkshop/libcurl-transport";
import { baremuxPath } from "@mercuryworkshop/bare-mux/node";
import mongoose, { Schema } from "mongoose";
import bcrypt from "bcryptjs";
import session from "express-session";
import connectMongo from "connect-mongo";

const __dirname = dirname(fileURLToPath(import.meta.url));
const publicPath = join(__dirname, "../public");

// ── Models — registered before connect ──────────────────
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

// ── Wisp ─────────────────────────────────────────────────
logging.set_level(logging.NONE);
Object.assign(wisp.options, {
  allow_udp_streams: false,
  dns_servers: ["1.1.1.3", "1.0.0.3"],
});

// ── Session middleware ───────────────────────────────────
const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || "kairo-secret",
  resave: false,
  saveUninitialized: false,
  store: connectMongo.create({ mongoUrl: process.env.MONGO_URI }),
  cookie: { secure: false, maxAge: 7 * 24 * 60 * 60 * 1000 }
});

function saveSession(req) {
  return new Promise((resolve, reject) =>
    req.raw.session.save(err => err ? reject(err) : resolve())
  );
}

// ── Fastify ──────────────────────────────────────────────
const fastify = Fastify({
  serverFactory: (handler) => {
    const srv = createServer();
    srv.keepAliveTimeout = 65000;
    srv.headersTimeout = 66000;
    srv
      .on("request", (req, res) => {
        // Required by scramjet for SharedArrayBuffer
        res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
        res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
        sessionMiddleware(req, res, () => handler(req, res));
      })
      .on("upgrade", (req, socket, head) => {
        if (req.url.endsWith("/wisp/")) {
          socket.setNoDelay(true);
          wisp.routeRequest(req, socket, head);
        } else {
          socket.end();
        }
      });
    return srv;
  },
});

fastify.addContentTypeParser("application/json", { parseAs: "string" }, (req, body, done) => {
  try { done(null, JSON.parse(body)); } catch (e) { done(e); }
});

// ── Static — public FIRST so sendFile works ──────────────
await fastify.register(fastifyStatic, {
  root: publicPath,
  decorateReply: true,
  maxAge: 60 * 1000,
});
await fastify.register(fastifyStatic, {
  root: scramjetPath,
  prefix: "/scram/",
  decorateReply: false,
  maxAge: 7 * 24 * 60 * 60 * 1000,
  immutable: true,
});
await fastify.register(fastifyStatic, {
  root: libcurlPath,
  prefix: "/libcurl/",
  decorateReply: false,
  maxAge: 7 * 24 * 60 * 60 * 1000,
  immutable: true,
});
await fastify.register(fastifyStatic, {
  root: baremuxPath,
  prefix: "/baremux/",
  decorateReply: false,
  maxAge: 7 * 24 * 60 * 60 * 1000,
  immutable: true,
});

// ── Auth helpers ─────────────────────────────────────────
const loggedIn  = (req) => !!req.raw.session?.username;
const adminOnly = (req) => !!req.raw.session?.isAdmin;

// ── Page routes ──────────────────────────────────────────
fastify.get("/", async (req, reply) => {
  if (!loggedIn(req)) return reply.redirect("/login.html");
  return reply.sendFile("index.html");
});

fastify.get("/admin", async (req, reply) => {
  if (!adminOnly(req)) return reply.redirect("/login.html");
  return reply.sendFile("admin.html");
});

// ── API ──────────────────────────────────────────────────
let pinsCache = null;
fastify.get("/api/pins", async (req, reply) => {
  if (!loggedIn(req)) return reply.code(401).send({ error: "Unauthorized" });
  if (!pinsCache) pinsCache = JSON.parse(readFileSync(join(__dirname, "../config.json"), "utf8"));
  reply.header("Cache-Control", "public, max-age=60");
  return { pins: pinsCache.pins };
});

fastify.post("/api/login", async (req) => {
  const { username, password } = req.body || {};
  if (!username || !password) return { success: false, error: "Missing fields" };
  const user = await User.findOne({ username });
  if (!user) return { success: false, error: "Invalid credentials" };
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return { success: false, error: "Invalid credentials" };
  req.raw.session.username = username;
  req.raw.session.isAdmin = username === "admin";
  req.raw.session.displayName = user.displayName || username;
  await saveSession(req);
  return { success: true, isAdmin: req.raw.session.isAdmin, displayName: req.raw.session.displayName };
});

fastify.post("/api/logout", async (req) => {
  await new Promise(r => req.raw.session.destroy(r));
  return { success: true };
});

fastify.get("/api/me", async (req) => {
  const s = req.raw.session;
  if (!s?.username) return { loggedIn: false };
  return { loggedIn: true, username: s.username, displayName: s.displayName || s.username, isAdmin: !!s.isAdmin };
});

fastify.get("/api/users", async (req, reply) => {
  if (!adminOnly(req)) return reply.code(401).send({ error: "Unauthorized" });
  return User.find({}, { password: 0, proxyCookies: 0 });
});

fastify.post("/api/users", async (req, reply) => {
  if (!adminOnly(req)) return reply.code(401).send({ error: "Unauthorized" });
  const { username, password, displayName } = req.body || {};
  if (!username || !password) return { success: false, error: "Missing fields" };
  try {
    const hash = await bcrypt.hash(password, 10);
    await User.create({ username, password: hash, displayName: displayName || username });
    return { success: true };
  } catch { return { success: false, error: "Username already exists" }; }
});

fastify.delete("/api/users/:username", async (req, reply) => {
  if (!adminOnly(req)) return reply.code(401).send({ error: "Unauthorized" });
  if (req.params.username === "admin") return { success: false, error: "Cannot delete admin" };
  await User.deleteOne({ username: req.params.username });
  return { success: true };
});

fastify.get("/api/cookies", async (req, reply) => {
  if (!loggedIn(req)) return reply.code(401).send({ error: "Unauthorized" });
  const user = await User.findOne({ username: req.raw.session.username }, { proxyCookies: 1 });
  return { cookies: user?.proxyCookies || "" };
});

fastify.post("/api/cookies", async (req, reply) => {
  if (!loggedIn(req)) return reply.code(401).send({ error: "Unauthorized" });
  const { cookies } = req.body || {};
  if (typeof cookies !== "string") return { success: false };
  await User.updateOne({ username: req.raw.session.username }, { $set: { proxyCookies: cookies.slice(0, 65536) } });
  return { success: true };
});

fastify.delete("/api/cookies", async (req, reply) => {
  if (!loggedIn(req)) return reply.code(401).send({ error: "Unauthorized" });
  await User.updateOne({ username: req.raw.session.username }, { $set: { proxyCookies: "" } });
  return { success: true };
});

fastify.get("/api/bookmarklets", async (req, reply) => {
  if (!loggedIn(req)) return reply.code(401).send({ error: "Unauthorized" });
  return Bookmarklet.find({}).sort({ createdAt: -1 });
});

fastify.post("/api/bookmarklets", async (req, reply) => {
  if (!adminOnly(req)) return reply.code(401).send({ error: "Unauthorized" });
  const { name, description, code } = req.body || {};
  if (!name || !code) return { success: false, error: "Name and code required" };
  try {
    const bm = await Bookmarklet.create({ name, description: description || "", code });
    return { success: true, bookmarklet: bm };
  } catch (e) { return { success: false, error: e.message }; }
});

fastify.delete("/api/bookmarklets/:id", async (req, reply) => {
  if (!adminOnly(req)) return reply.code(401).send({ error: "Unauthorized" });
  await Bookmarklet.deleteOne({ _id: req.params.id });
  return { success: true };
});

fastify.setNotFoundHandler((req, reply) => {
  reply.code(404).type("text/html").sendFile("404.html");
});

// ── Start ────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT || "3000");
await fastify.listen({ port: PORT, host: "0.0.0.0" });
console.log(`Kairo listening on port ${PORT}`);
