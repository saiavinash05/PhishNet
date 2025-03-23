const express = require("express");
const axios = require("axios");
const cors = require("cors");
require("dotenv").config();
const app = express();
const port = 5001;

app.use(express.json());

// CORS Configuration
const allowedOrigins = [
  "chrome-extension://cgplnmomiemafejcojlhejobbbdbmlgg", // Your extension's origin
  "http://localhost:5001", // Allow requests from your local server
];
app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
  })
);

// DNS Blacklist APIs
const dnsBlacklistApis = [
  {
    url: "https://www.virustotal.com/api/v3/urls",
    apiKey: process.env.VIRUSTOTAL_API_KEY,
    method: "POST", // VirusTotal requires a POST request
  },
  {
    url: "https://api.urlscan.io/v1/scan/",
    apiKey: process.env.URLSCAN_API_KEY,
    method: "POST", // URLScan.io requires a POST request
  },
];

// WHOIS API (WhoisXMLAPI)
const whoisApi = "https://www.whoisxmlapi.com/whoisserver/WhoisService";
const whoisApiKey = process.env.WHOISXML_API_KEY;

// SSL Validation API (SSL Labs)
const sslValidationApi = "https://api.ssllabs.com/api/v3/analyze";

// Phishing Detection API (VirusTotal)
const phishingDetectionApi = "https://www.virustotal.com/api/v3/urls";
const virusTotalApiKey = process.env.VIRUSTOTAL_API_KEY;

// URL Expansion API (Unshorten.me)
const unshortenApi = "https://unshorten.me/json/";

// Trusted Domains List
const trustedDomains = [
  "google.com",
  "facebook.com",
  "paypal.com",
  "amazon.com",
];

// In-Memory Cache
const memoryCache = new Map();
const cacheDuration = 3600000; // 1 hour

// Rate Limiting
const rateLimitMap = new Map();
const rateLimitDuration = 5000; // 5 seconds
const maxRequests = 5;

// Validate Domain
function validateDomain(domain) {
  // Non-ASCII characters
  if (/[^\x00-\x7F]/.test(domain)) {
    return { isValid: false, reason: "Domain contains non-ASCII characters" };
  }

  // Homoglyphs check
  const homoglyphs = {
    а: "a",
    е: "e",
    о: "o",
    с: "c",
    р: "p",
    у: "y",
    х: "x",
  };
  const normalizedDomain = domain
    .split("")
    .map((char) => homoglyphs[char] || char)
    .join("");
  if (normalizedDomain !== domain) {
    return { isValid: false, reason: "Domain contains homoglyphs" };
  }

  return { isValid: true };
}

// Validate URL Format
function isValidUrl(url) {
  try {
    // Basic regex to check for valid URL format
    const urlPattern =
      /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/;
    if (!urlPattern.test(url)) {
      return false;
    }
    new URL(url); // This will throw an error if the URL is invalid
    return true;
  } catch {
    return false;
  }
}

// Expand Shortened URL
async function expandUrl(url) {
  try {
    const response = await axios.get(`${unshortenApi}${url}`);
    return response.data.resolved_url || url; // Return original URL if expansion fails
  } catch (error) {
    console.error("URL Expansion Error:", error);
    return url; // Return original URL if expansion fails
  }
}

// Extract Domain from URL
function extractDomain(url) {
  try {
    const parsedUrl = new URL(url);
    return parsedUrl.hostname;
  } catch (error) {
    console.error("Error extracting domain:", error);
    return null; // Return null for invalid URLs
  }
}

// Check URL for Phishing
app.post("/check-url", async (req, res) => {
  const { url } = req.body;

  // Rate Limiting
  const rateLimitResult = rateLimitCheck(url);
  if (rateLimitResult) {
    return res.status(429).json({ error: rateLimitResult.reason });
  }

  // Validate URL format
  if (!isValidUrl(url)) {
    return res.status(400).json({ error: "Invalid URL format" });
  }

  // Expand shortened URL
  // Expand shortened URL
  let expandedUrl;
  try {
    expandedUrl = await expandUrl(url);
    console.log("Expanded URL result:", expandedUrl);
  } catch (error) {
    console.error("URL Expansion Error:", error);
    expandedUrl = ""; // Set as empty string to fallback
  }

  // Fallback to original if expansion failed or returned empty
  const finalUrl = expandedUrl || url; // If expansion fails, use the original URL
  console.log("Final URL used for domain extraction:", finalUrl);

  // Validate the URL format before extracting the domain
  let domain;
  try {
    // Only proceed if finalUrl is a valid URL
    if (!isValidUrl(finalUrl)) {
      return res.status(400).json({ error: "Invalid URL format" });
    }
    domain = new URL(finalUrl).hostname;
    console.log("Extracted domain:", domain);
  } catch (error) {
    console.error("Error extracting domain:", error);
    return res.status(400).json({ error: "Failed to extract domain" });
  }

  // Validate Domain (ensure it's a proper domain)
  try {
    const extractedDomain = extractDomain(domain);
    if (!extractedDomain) {
      return res.status(400).json({
        error: "Invalid or potentially harmful URL scheme",
      });
    }
    domain = extractedDomain; // Update domain with the extracted value
  } catch (error) {
    console.error("Error extracting domain:", error);
    return res.status(400).json({ error: "Invalid URL" });
  }

  // Domain validation
  const domainValidation = validateDomain(domain);
  if (!domainValidation.isValid) {
    return res.status(400).json({ error: domainValidation.reason });
  }

  // Check Cache (per domain)
  const cachedResult = getCachedResult(domain);
  if (cachedResult) {
    return res.status(200).json(cachedResult);
  }

  // Run all checks in parallel
  const [dnsResult, typoResult, whoisResult, sslResult, phishingResult] =
    await Promise.all([
      isDnsBlacklisted(domain),
      isTypoSquatting(domain),
      getWhoisData(domain),
      hasValidCertificate(domain),
      isPhishing(expandedUrl),
    ]);

  const result = {
    isMalicious:
      dnsResult || typoResult || whoisResult || !sslResult || phishingResult,
    reasons: {
      dnsBlacklisted: dnsResult,
      typoSquatting: typoResult,
      newlyRegistered: whoisResult,
      invalidSSL: !sslResult,
      phishing: phishingResult,
    },
  };

  // Cache the result (per domain)
  setCache(domain, result);

  // Send response
  if (result.isMalicious) {
    console.log("Malicious URL detected:", domain); // Log malicious URL
    return res.status(403).json({
      error: "Access blocked",
      message:
        "This website is potentially malicious. Proceed at your own risk.",
      reasons: result.reasons,
      bypassUrl: expandedUrl,
    });
  } else {
    console.log("Safe URL:", domain); // Log safe URL
    return res.status(200).json({
      isMalicious: false,
      message: "This website is safe.",
    });
  }
});

// DNS Blacklist Check
async function isDnsBlacklisted(domain) {
  for (const api of dnsBlacklistApis) {
    try {
      console.log("Checking DNS blacklist for domain:", domain); // Log the domain being checked
      const response = await axios.post(
        api.url,
        { url: domain },
        {
          headers: {
            "x-apikey": api.apiKey,
            "Content-Type": "application/json",
          },
        }
      );
      const stats = response.data.data.attributes.last_analysis_stats;
      console.log("DNS blacklist result:", stats); // Log the result
      return stats.malicious > 0 || stats.phishing > 0 || stats.malware > 0;
    } catch (error) {
      console.error(
        `DNS Blacklist API Error (${api.url}):`,
        error.response?.data || error.message
      ); // Log the error
      return false;
    }
  }
  return false;
}

// Typo-Squatting Check
function isTypoSquatting(domain) {
  return trustedDomains.some(
    (trusted) => levenshteinDistance(domain, trusted) <= 2
  );
}

// WHOIS Lookup
async function getWhoisData(domain) {
  try {
    const response = await axios.get(
      `${whoisApi}?domainName=${domain}&apiKey=${whoisApiKey}`
    );

    // Check if the response contains the expected data
    if (
      !response.data ||
      !response.data.WhoisRecord ||
      !response.data.WhoisRecord.createdDate
    ) {
      console.error("WHOIS API Error: Invalid response format");
      return false;
    }

    const creationDate = new Date(response.data.WhoisRecord.createdDate);
    const oneMonthAgo = new Date();
    oneMonthAgo.setMonth(oneMonthAgo.getMonth() - 1);
    return creationDate > oneMonthAgo;
  } catch (error) {
    console.error("WHOIS API Error:", error);
    return false;
  }
}

// SSL Validation Check
async function hasValidCertificate(domain) {
  try {
    console.log("Checking SSL for domain:", domain); // Log the domain being checked
    const response = await axios.get(`${sslValidationApi}?host=${domain}`);
    return response.data.endpoints.some((endpoint) => endpoint.grade >= "A");
  } catch (error) {
    console.error(
      "SSL Validation API Error:",
      error.response?.data || error.message
    ); // Log the error
    return false;
  }
}

// Phishing Detection Check
async function isPhishing(url) {
  try {
    console.log("Checking phishing for URL:", url); // Log the URL being checked
    const response = await axios.post(
      phishingDetectionApi,
      { url: url },
      {
        headers: {
          "x-apikey": virusTotalApiKey,
          "Content-Type": "application/json",
        },
      }
    );
    const stats = response.data.data.attributes.last_analysis_stats;
    console.log("Phishing check result:", stats); // Log the result
    return stats.malicious > 0 || stats.phishing > 0;
  } catch (error) {
    console.error(
      "Phishing Detection API Error:",
      error.response?.data || error.message
    ); // Log the error
    return false;
  }
}

// Levenshtein Distance Function
function levenshteinDistance(a, b) {
  let prev = Array(b.length + 1)
    .fill(0)
    .map((_, i) => i);
  let curr = Array(b.length + 1).fill(0);

  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[b.length];
}

// Rate Limiting
function rateLimitCheck(url) {
  const now = Date.now();
  if (!rateLimitMap.has(url)) {
    rateLimitMap.set(url, { count: 1, lastRequest: now });
    return null;
  }

  const { count, lastRequest } = rateLimitMap.get(url);
  if (now - lastRequest < rateLimitDuration) {
    if (count >= maxRequests) {
      return { reason: "Rate limit exceeded. Try again later." };
    }
    rateLimitMap.set(url, { count: count + 1, lastRequest: now });
  } else {
    rateLimitMap.set(url, { count: 1, lastRequest: now });
  }
  return null;
}

// Caching
function getCachedResult(domain) {
  if (memoryCache.has(domain)) {
    const { data, timestamp } = memoryCache.get(domain);
    if (Date.now() - timestamp < cacheDuration) {
      return data;
    }
  }
  return null;
}

function setCache(domain, data) {
  memoryCache.set(domain, { data, timestamp: Date.now() });
}

// Serve Frontend
const path = require("path");
app.use(express.static(path.join(__dirname, "..", "Frontend")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "..", "Frontend", "index.html"));
});

// Start the server
app.listen(port, () => {
  console.log(`Backend running at http://localhost:${port}`);
});
