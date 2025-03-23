// backend/logHandler.js

const express = require("express");
const mongoose = require("mongoose");
const router = express.Router();
require("dotenv").config(); // Load MONGO_URI if needed

// MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI || "mongodb://localhost:27017/phishing_logs", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB Connected for Logs"))
  .catch((err) => console.error("❌ MongoDB Connection Error:", err));

// Schema for log entries
const logSchema = new mongoose.Schema({
  url: String,
  timestamp: { type: Date, default: Date.now },
  ml_result: String,
  virustotal_result: String,
  abuseipdb_result: String,
  whois_result: String,
  ssl_result: String,
  final_verdict: String,
});

// Model
const Log = mongoose.model("Log", logSchema);

// ✅ POST /log — Save a scan log
router.post("/log", async (req, res) => {
  try {
    const logEntry = new Log(req.body);
    await logEntry.save();
    res.status(201).json({ message: "✅ Log saved successfully" });
  } catch (err) {
    console.error("❌ Error saving log:", err);
    res.status(500).json({ error: "Failed to save log" });
  }
});

// ✅ GET /logs — Fetch all logs (for dashboard)
router.get("/logs", async (req, res) => {
  try {
    const logs = await Log.find().sort({ timestamp: -1 }); // Latest first
    res.json(logs);
  } catch (err) {
    console.error("❌ Error fetching logs:", err);
    res.status(500).json({ error: "Failed to fetch logs" });
  }
});

module.exports = router;
