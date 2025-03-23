document
  .getElementById("checkUrlButton")
  .addEventListener("click", async () => {
    const url = document.getElementById("urlInput").value;
    const resultDiv = document.getElementById("result");

    try {
      const response = await fetch("http://localhost:5001/check-url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });

      const data = await response.json();

      if (response.status === 403) {
        resultDiv.innerHTML = `
        <p class="error">${data.message}</p>
        <p>Reasons:</p>
        <ul>
          <li>DNS Blacklisted: ${data.reasons.dnsBlacklisted.toString()}</li>
          <li>Typo-Squatting: ${data.reasons.typoSquatting.toString()}</li>
          <li>Newly Registered: ${data.reasons.newlyRegistered.toString()}</li>
          <li>Invalid SSL: ${data.reasons.invalidSSL.toString()}</li>
          <li>Phishing: ${data.reasons.phishing.toString()}</li>
        </ul>
        <button id="proceedButton">Proceed at your own risk</button>
      `;

        document
          .getElementById("proceedButton")
          .addEventListener("click", () => {
            window.location.href = data.bypassUrl; 
          });
      } else if (response.ok) {
        resultDiv.innerHTML = `
        <p class="success">${data.message}</p>
        <a href="${url}" target="_blank" rel="noopener noreferrer">Visit the website</a>
      `;
      } else {
        resultDiv.innerHTML = `<p class="error">An error occurred while checking the URL.</p>`;
      }
    } catch (error) {
      resultDiv.innerHTML = `<p class="error">An error occurred while checking the URL.</p>`;
    }
  });
