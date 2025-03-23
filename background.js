// Cache to store URL check results
const urlCache = new Map();

// Function to check if a URL is safe
async function checkUrlSafety(url) {
  if (urlCache.has(url)) {
    return urlCache.get(url);
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
    urlCache.set(url, data.isMalicious); // Cache the result
    return data.isMalicious;
  } catch (error) {
    console.error("Error checking URL:", error);
    return false; // Assume URL is safe if the check fails
  }
}

// Intercept network requests
chrome.webRequest.onBeforeRequest.addListener(
  async (details) => {
    const url = details.url;

    // Check if the URL is safe
    const isMalicious = await checkUrlSafety(url);

    if (isMalicious) {
      // Show a custom warning popup
      const userConfirmed = await showWarningPopup(url);

      if (!userConfirmed) {
        // Block the request if the user cancels
        return { cancel: true };
      }
    }

    // Allow the request to proceed
    return { cancel: false };
  },
  { urls: ["<all_urls>"] }, // Intercept all URLs
  ["blocking"]
);

// Function to show a custom warning popup
function showWarningPopup(url) {
  return new Promise((resolve) => {
    chrome.windows.create(
      {
        url: chrome.runtime.getURL("warning.html"),
        type: "popup",
        width: 400,
        height: 300,
      },
      (popupWindow) => {
        // Listen for messages from the warning popup
        chrome.runtime.onMessage.addListener(function listener(message) {
          if (message.action === "proceed") {
            resolve(true); // User chose to proceed
          } else if (message.action === "block") {
            resolve(false); // User chose to block
          }
          chrome.runtime.onMessage.removeListener(listener); // Clean up the listener
        });
      }
    );
  });
}
