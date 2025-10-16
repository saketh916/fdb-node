// ---------- Imports ----------
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const dotenv = require("dotenv");
dotenv.config();

// Assuming your models files are correctly linked
const User = require("./models/User");
const SearchHistory = require("./models/SearchHistory");

// ---------- App Setup ----------
const app = express();

// ✅ CORS (allows localhost + production frontend)
app.use(
  cors({
    origin: [
      "http://localhost:5173", // local dev
      "https://your-frontend-domain.vercel.app", // old Vercel frontend placeholder
      // 🔑 NEW: Add the AWS Amplify domain to the whitelist
      "https://main.dd9f3o4tcnlx2.amplifyapp.com" 
    ],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
  })
);
app.use(express.json());

// ---------- MongoDB Connection ----------
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
  })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB connection error:", err.message));

// ---------- Auth Middleware ----------
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  try {
    // Use the same secret as the login route
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "default_secret");
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

// ---------- Health Check ----------
app.get("/", (req, res) => {
  res.status(200).json({ message: "🚀 Feedback Analysis API is live on Vercel!" });
});

// ---------- Auth Routes ----------

// Registration Route - MODIFIED to return JWT token for auto-login
app.post("/api/register", async (req, res) => {
  const { email, password } = req.body;

  try {
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ email, password: hashedPassword });
    await newUser.save();

    // Generate JWT Token for immediate login
    const token = jwt.sign(
      { id: newUser._id, email: newUser.email },
      process.env.JWT_SECRET || "default_secret",
      { expiresIn: "1h" }
    );

    // Return the token and user email
    res.status(201).json({ 
      message: "Registration successful! Logging you in.",
      token,
      email: newUser.email
    });
  } catch (err) {
    console.error("Register Error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

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
      process.env.JWT_SECRET || "default_secret",
      { expiresIn: "1h" }
    );

    res.status(200).json({
      message: "Login successful",
      token,
      email: user.email
    });
  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// ---------- Search History ----------
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

// ---------- User Profile ----------
app.get("/api/user-profile", authenticate, (req, res) => {
  res.json({ email: req.user.email });
});

// ---------- Export App for Vercel ----------
module.exports = app;
