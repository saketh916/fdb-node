const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const dotenv = require("dotenv");
dotenv.config();

const User = require("../models/User");
const SearchHistory = require("../models/SearchHistory");

const app = express();

// ✅ CORS config
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "https://your-frontend-domain.vercel.app"
    ],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
  })
);
app.use(express.json());

// ✅ Connect to MongoDB (safe for serverless)
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("Mongo error:", err.message));

// ✅ Middleware
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  jwt.verify(token, "secret", (err, decoded) => {
    if (err) return res.status(401).json({ message: "Unauthorized" });
    req.user = decoded;
    next();
  });
};

// ✅ Routes
app.get("/", (req, res) => res.json({ message: "API is live 🚀" }));

app.post("/api/register", async (req, res) => {
  const { email, password } = req.body;
  try {
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: "User already exists" });

    const hashed = await bcrypt.hash(password, 10);
    await new User({ email, password: hashed }).save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id, email: user.email }, "secret", { expiresIn: "1h" });
    res.json({ message: "Login successful", token, email: user.email });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/api/search-history", authenticate, async (req, res) => {
  try {
    const { searchUrl, searchResponse } = req.body;
    const userEmail = req.user.email;
    await new SearchHistory({ userEmail, searchUrl, searchResponse }).save();
    res.status(201).json({ message: "Search history saved successfully" });
  } catch (err) {
    console.error("Search save error:", err);
    res.status(500).json({ message: "Error saving search history" });
  }
});

app.get("/api/search-history", authenticate, async (req, res) => {
  try {
    const userEmail = req.user.email;
    const history = await SearchHistory.find({ userEmail }).sort({ timestamp: -1 });
    res.json(history);
  } catch (err) {
    console.error("Search fetch error:", err);
    res.status(500).json({ message: "Error fetching search history" });
  }
});

// ✅ Export (no app.listen)
module.exports = app;
