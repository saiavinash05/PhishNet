// Cache to store URL check results
const urlCache = new Map();
const CACHE_DURATION = 3600000; // 1 hour in milliseconds

// Function to check if a URL is safe
async function checkUrlSafety(url) {
  // Check if the URL is in the cache and the cache is still valid
  if (urlCache.has(url)) {
    const { isMalicious, timestamp } = urlCache.get(url);
    if (Date.now() - timestamp < CACHE_DURATION) {
      console.log(
        "Returning cached result for URL:",
        url,
        "Result:",
        isMalicious
      ); // Debugging
      return isMalicious; // Return cached result
    }
  }

  try {
    console.log("Checking URL with backend:", url); // Debugging
    const response = await fetch("http://localhost:5001/check-url", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}`);
    }

    const data = await response.json();
    console.log("Backend response for URL:", url, "Response:", data); // Debugging

    // Ensure the backend response has the expected structure
    const isMalicious = data.isMalicious || false; // Default to false if not specified

    // Cache the result with a timestamp
    urlCache.set(url, { isMalicious, timestamp: Date.now() });

    return isMalicious;
  } catch (error) {
    console.error("Error checking URL:", url, "Error:", error); // Debugging
    // Instead of assuming the URL is safe, you might want to block it or handle it differently
    return true; // Assume URL is malicious if the check fails (safer approach)
  }
}

// Intercept network requests
chrome.webRequest.onBeforeRequest.addListener(
  async (details) => {
    const url = details.url;
    console.log("Intercepted URL:", url); // Debugging

    // Check if the URL is safe
    const isMalicious = await checkUrlSafety(url);
    console.log("Is Malicious:", isMalicious); // Debugging

    if (isMalicious) {
      console.log("Malicious URL detected:", url);

      // Show a custom warning popup
      const userConfirmed = await showWarningPopup(url);

      if (!userConfirmed) {
        // Block the request if the user cancels
        console.log("Blocking URL:", url); // Debugging
        return { cancel: true };
      }
    }

    // Allow the request to proceed
    console.log("Allowing URL:", url); // Debugging
    return { cancel: false };
  },
  { urls: ["<all_urls>"] }, // Intercept all URLs
  ["blocking"] // Block the request if necessary
);

// Function to show a custom warning popup
function showWarningPopup(url) {
  return new Promise((resolve) => {
    // Create a warning popup window
    chrome.windows.create(
      {
        url: chrome.runtime.getURL(
          `warning.html?url=${encodeURIComponent(url)}`
        ),
        type: "popup",
        width: 400,
        height: 300,
      },
      (popupWindow) => {
        // Handle popup window closing unexpectedly
        const onWindowRemoved = (windowId) => {
          if (windowId === popupWindow.id) {
            // If the popup is closed without user action, assume the user wants to block the URL
            resolve(false);
            chrome.windows.onRemoved.removeListener(onWindowRemoved); // Clean up the listener
          }
        };

        chrome.windows.onRemoved.addListener(onWindowRemoved);

        // Listen for messages from the warning popup
        const messageListener = (message, sender, sendResponse) => {
          if (sender.url === chrome.runtime.getURL("warning.html")) {
            if (message.action === "proceed") {
              resolve(true); // User chose to proceed
            } else if (message.action === "block") {
              resolve(false); // User chose to block
            }
            chrome.runtime.onMessage.removeListener(messageListener); // Clean up the listener
          }
        };

        chrome.runtime.onMessage.addListener(messageListener);
      }
    );
  });
}
