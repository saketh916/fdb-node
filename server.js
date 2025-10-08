const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const dotenv = require("dotenv");
dotenv.config();

// Import Models
const User = require("./models/User");
const SearchHistory = require("./models/SearchHistory");

const app = express();

// ✅ CORS Setup
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

// ✅ MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// ✅ Auth Middleware
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  jwt.verify(token, "secret", (err, decoded) => {
    if (err) return res.status(401).json({ message: "Unauthorized" });
    req.user = decoded;
    next();
  });
};

// ✅ Base route (for testing)
app.get("/", (req, res) => {
  res.json({ message: "🚀 Feedback Analysis API is live!" });
});

// ✅ Register Route
app.post("/api/register", async (req, res) => {
  const { email, password } = req.body;
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    console.error("Register Error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// ✅ Login Route
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user)
      return res.status(400).json({ message: "Invalid email or password" });

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid)
      return res.status(400).json({ message: "Invalid email or password" });

    const token = jwt.sign(
      { id: user._id, email: user.email },
      "secret",
      { expiresIn: "1h" }
    );

    res.status(200).json({ message: "Login successful", token, email: user.email });
  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// ✅ Save Search History
app.post("/api/search-history", authenticate, async (req, res) => {
  const { searchUrl, searchResponse } = req.body;
  const userEmail = req.user.email;

  try {
    const record = new SearchHistory({ userEmail, searchUrl, searchResponse });
    await record.save();
    res.status(201).json({ message: "Search history saved successfully" });
  } catch (err) {
    console.error("Save Search Error:", err);
    res.status(500).json({ message: "Error saving search history" });
  }
});

// ✅ Fetch Search History
app.get("/api/search-history", authenticate, async (req, res) => {
  const userEmail = req.user.email;
  try {
    const history = await SearchHistory.find({ userEmail }).sort({ timestamp: -1 });
    res.json(history);
  } catch (err) {
    console.error("Fetch Search Error:", err);
    res.status(500).json({ message: "Error fetching search history" });
  }
});

// ✅ User Profile
app.get("/api/user-profile", authenticate, (req, res) => {
  res.json({ email: req.user.email });
});

// ✅ Export app for Vercel (❗ DO NOT use app.listen)
module.exports = app;
