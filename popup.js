document.getElementById("check").addEventListener("click", async () => {
    const url = document.getElementById("url").value;
  
    if (!url) {
      document.getElementById("result").innerText = "Please enter a URL.";
      return;
    }
  
    try {
      const response = await fetch("http://localhost:5001/check-url", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url }),
      });
  
      const data = await response.json();
  
      if (data.isMalicious) {
        document.getElementById("result").innerText =
          "Warning: This URL is potentially malicious!";
      } else {
        document.getElementById("result").innerText = "This URL is safe.";
      }
    } catch (error) {
      console.error("Error checking URL:", error);
      document.getElementById("result").innerText =
        "An error occurred while checking the URL.";
    }
  });