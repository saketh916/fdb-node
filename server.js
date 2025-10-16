// ---------- Imports ----------
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const dotenv = require("dotenv");

dotenv.config();

const User = require("./models/User");
const SearchHistory = require("./models/SearchHistory");

const app = express();

// ---------- CORS: Strictly Fixed ----------
const allowedOrigins = [
  "http://localhost:5173",
  "https://main.dd9f3o4tcnlx2.amplifyapp.com",
];

// 🔥 universal middleware before anything else
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET,POST,PUT,DELETE,OPTIONS"
  );
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization"
  );
  res.setHeader("Access-Control-Allow-Credentials", "true");

  // handle preflight requests immediately
  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }
  next();
});

app.use(express.json());

// ---------- MongoDB ----------
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB connection error:", err.message));

// ---------- Auth Middleware ----------
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "default_secret");
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

// ---------- Health Check ----------
app.get("/", (req, res) => {
  res.status(200).json({ message: "🚀 Feedback Analysis API is live!" });
});

// ---------- Auth Routes ----------
app.post("/api/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "Email and password required" });

    const existing = await User.findOne({ email });
    if (existing)
      return res.status(400).json({ message: "User already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const newUser = new User({ email, password: hashed });
    await newUser.save();

    const token = jwt.sign(
      { id: newUser._id, email: newUser.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.status(201).json({
      message: "Registration successful!",
      token,
      email: newUser.email,
    });
  } catch (err) {
    console.error("Register Error:", err);
    res.status(500).json({ message: err.message || "Internal server error" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user)
      return res.status(400).json({ message: "Invalid email or password" });

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid)
      return res.status(400).json({ message: "Invalid email or password" });

    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ message: "Login successful", token, email: user.email });
  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ message: err.message || "Internal server error" });
  }
});

// ---------- Search History ----------
app.post("/api/search-history", authenticate, async (req, res) => {
  try {
    const { searchUrl, searchResponse } = req.body;
    const record = new SearchHistory({
      userEmail: req.user.email,
      searchUrl,
      searchResponse,
    });
    await record.save();
    res.status(201).json({ message: "Saved successfully" });
  } catch (err) {
    console.error("Save Search Error:", err);
    res.status(500).json({ message: "Error saving search history" });
  }
});

app.get("/api/search-history", authenticate, async (req, res) => {
  try {
    const history = await SearchHistory.find({ userEmail: req.user.email }).sort({
      timestamp: -1,
    });
    res.json(history);
  } catch (err) {
    console.error("Fetch Search Error:", err);
    res.status(500).json({ message: "Error fetching search history" });
  }
});

// ---------- User Profile ----------
app.get("/api/user-profile", authenticate, (req, res) => {
  res.json({ email: req.user.email });
});

// ---------- Export App ----------
module.exports = app;
