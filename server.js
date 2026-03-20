require("dotenv").config();
const express = require("express");
const { createServer } = require("http");
const { WispServer } = require("wisp-server-node");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const path = require("path");
const fs = require("fs");

const app = express();
const server = createServer(app);

mongoose.connect(process.env.MONGO_URI).then(async () => {
  console.log("MongoDB connected");
  await seedAdmin();
}).catch(err => console.error("MongoDB error:", err));

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model("User", userSchema);

async function seedAdmin() {
  const existing = await User.findOne({ username: "admin" });
  if (!existing) {
    const hash = await bcrypt.hash("stu8976@admin", 10);
    await User.create({ username: "admin", password: hash });
    console.log("Admin user created");
  }
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || "osazee-secret",
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

const scramjetPath = path.dirname(require.resolve("@mercuryworkshop/scramjet"));
app.use("/scramjet/", express.static(scramjetPath));
app.use(express.static(path.join(__dirname, "public")));

function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) return next();
  res.status(401).json({ error: "Unauthorized" });
}

app.get("/api/pins", (req, res) => {
  const config = JSON.parse(fs.readFileSync(path.join(__dirname, "config.json")));
  res.json({ pins: config.pins, games: config.games });
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.json({ success: false, error: "Invalid credentials" });
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.json({ success: false, error: "Invalid credentials" });
  req.session.isAdmin = username === "admin";
  req.session.username = username;
  res.json({ success: true, isAdmin: req.session.isAdmin });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get("/api/me", (req, res) => {
  if (!req.session.username) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, username: req.session.username, isAdmin: !!req.session.isAdmin });
});

app.get("/api/users", requireAdmin, async (req, res) => {
  const users = await User.find({}, { password: 0 });
  res.json(users);
});

app.post("/api/users", requireAdmin, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.json({ success: false, error: "Missing fields" });
  try {
    const hash = await bcrypt.hash(password, 10);
    await User.create({ username, password: hash });
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

app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

const wispServer = new WispServer({ logLevel: 0 });
wispServer.attach(server, "/wisp/");

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Running on port ${PORT}`));
