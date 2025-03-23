const express = require("express");
const axios = require("axios");
const app = express();

app.use(express.json());

// Import the log handler
const logHandler = require("./logHandler");
app.use("/", logHandler);

// Endpoint to check URLs
app.post("/check-url", async (req, res) => {
  const { url } = req.body;

  try {
    // Forward URL to Python backend (urlChecker.py on port 5000)
    const pythonResponse = await axios.post(
      "http://127.0.0.1:5000/analyze-url",
      {
        url,
      }
    );

    // Forward URL to Node.js backend (check-url.js on port 5001)
    const nodeResponse = await axios.post("http://127.0.0.1:5001/check", {
      url,
    });

    // Combine results from both backends
    const isMalicious =
      pythonResponse.data.status === "malicious" ||
      nodeResponse.data.isMalicious;

    // Send response to the extension
    res.json({ isMalicious });
  } catch (error) {
    console.error("Error Message:", error.message);

    // Log detailed error information
    if (error.response) {
      console.error("Response Data:", error.response.data);
      console.error("Response Status:", error.response.status);
    } else if (error.request) {
      console.error("No response received from backend");
    }

    res.status(500).json({ error: "Backend error" });
  }
});

// Start the server
app.listen(3000, () => console.log("Express running on port 3000"));
