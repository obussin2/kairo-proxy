import "dotenv/config";
import { fileURLToPath } from "url";
import { join, dirname } from "path";
import { server as wisp } from "@mercuryworkshop/wisp-js/server";
import Fastify from "fastify";
import fastifyStatic from "@fastify/static";
import { scramjetPath } from "@mercuryworkshop/scramjet/path";
import { libcurlPath } from "@mercuryworkshop/libcurl-transport";
import { baremuxPath } from "@mercuryworkshop/bare-mux/node";
import mongoose, { Schema } from "mongoose";

const __dirname = dirname(fileURLToPath(import.meta.url));
const publicPath = join(__dirname, "../public"); // Adjust if your public folder is somewhere else

// 1. Initialize Fastify
const fastify = Fastify({ logger: false });

// 2. --- Static File Serving ---
// Serve your main website files (index.html, style.css, etc.)
fastify.register(fastifyStatic, {
  root: publicPath,
  prefix: "/",
});

// Serve the Proxy Engine (Scramjet)
fastify.register(fastifyStatic, {
  root: scramjetPath,
  prefix: "/scram/",
  decorateReply: false // Required when registering multiple static folders
});

// Serve the Multiplexer (BareMux)
fastify.register(fastifyStatic, {
  root: baremuxPath,
  prefix: "/baremux/",
  decorateReply: false
});

// Serve the Network Transport (Libcurl)
fastify.register(fastifyStatic, {
  root: libcurlPath,
  prefix: "/libcurl/",
  decorateReply: false
});

// 3. --- Wisp WebSocket Server (THIS FIXES THE BLACK SCREEN) ---
// This intercepts WebSocket requests and hands them to Wisp so the proxy gets internet
fastify.server.on("upgrade", (req, socket, head) => {
  if (req.url.endsWith("/wisp/")) {
    wisp.routeRequest(req, socket, head);
  } else {
    socket.end();
  }
});

// 4. --- Database Models ---
const User = mongoose.model("User", new Schema({
  username:     { type: String, unique: true },
  password:     String,
  displayName:  { type: String, default: "" },
  proxyCookies: { type: String, default: "" },
  createdAt:    { type: Date, default: Date.now }
}));

const Bookmarklet = mongoose.model("Bookmarklet", new Schema({
  name:        { type: String, required: true },
  description: { type: String },
  code:        { type: String, required: true }
}));

// 5. --- API Routes ---
// (Mocked basic auth checks for your existing routes based on your file)
const loggedIn = (req) => req.headers.authorization || true; // Replace with your real session check
const adminOnly = (req) => true; // Replace with your real admin check

fastify.get("/api/me", async (req, reply) => {
  return { loggedIn: true, displayName: "User", isAdmin: true }; // Dummy response so UI loads
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
  reply.sendFile("index.html"); // SPA fallback
});

// 6. --- Boot up ---
const start = async () => {
  try {
    if (process.env.MONGO_URI) {
      await mongoose.connect(process.env.MONGO_URI);
      console.log("✅ Connected to MongoDB");
    }
    
    // Start listening
    const port = process.env.PORT || 8080;
    await fastify.listen({ port: port, host: "0.0.0.0" });
    console.log(`🚀 Kairo Backend running at http://localhost:${port}`);
    console.log(`🔌 Wisp WebSocket listening on ws://localhost:${port}/wisp/`);
    
  } catch (err) {
    console.error("❌ Failed to start server:", err);
    process.exit(1);
  }
};

start();
