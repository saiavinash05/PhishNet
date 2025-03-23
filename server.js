const express = require("express");
const axios = require("axios");
const app = express();

app.use(express.json()); 

app.post("/check-url", async (req, res) => {
  const { url } = req.body;

  try {
    // Forward URL to Python backend
    const response = await axios.post("http://127.0.0.1:5000/analyze-url", {
      url,
    });

    // Extract status from Flask response
    res.json({ prediction: response.data.status });
  } catch (error) {
    console.error("Error Message:", error.message);

    // Log 
    if (error.response) {
      console.error("Response Data:", error.response.data);
      console.error("Response Status:", error.response.status);
    } else if (error.request) {
      console.error("No response received from Python backend");
    }

    res.status(500).json({ error: "Python backend error" });
  }
});

app.listen(3000, () => console.log("Express running on port 3000"));
