// Get the bypass link
const bypassLink = document.getElementById("bypass-link");

// Add a click event listener to the bypass link
bypassLink.addEventListener("click", (event) => {
  event.preventDefault();

  // Get the original URL from the query parameters
  const urlParams = new URLSearchParams(window.location.search);
  const originalUrl = urlParams.get("url");

  if (originalUrl) {
    // Redirect the user to the original URL
    window.location.href = originalUrl;
  }
});
