const express = require("express");
const axios = require("axios");
const cors = require("cors");
require("dotenv").config();
const app = express();
const port = 5001;

app.use(express.json());

const allowedOrigins = [
  "https://your-chrome-extension-id.chromiumapp.org",
  "http://localhost:5001", 
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
  },
  {
    url: "https://api.abuseipdb.com/api/v2/check",
    apiKey: process.env.ABUSEIPDB_API_KEY,
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

const trustedDomains = [
  "google.com",
  "facebook.com",
  "paypal.com",
  "amazon.com",
];

// In-Memory Cache
const memoryCache = new Map();
const cacheDuration = 3600000; 

// Rate Limiting
const rateLimitMap = new Map();
const rateLimitDuration = 5000; 
const maxRequests = 5;

// Validating domain
function validateDomain(domain) {
  // Non-ASCII chars
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

// URL format
function isValidUrl(url) {
  const urlPattern = /^(https?:\/\/)?([\w.-]+)\.([a-z]{2,})(\/\S*)?$/i;
  return urlPattern.test(url);
}

// URL expansion
async function expandUrl(url) {
  try {
    const response = await axios.get(`${unshortenApi}${url}`);
    return response.data.resolved_url;
  } catch (error) {
    console.error("URL Expansion Error:", error);
    return url; 
  }
}

// URL phishing check
app.post("/check-url", async (req, res) => {
  const { url } = req.body;

  const rateLimitResult = rateLimitCheck(url);
  if (rateLimitResult) {
    return res.status(429).json({ error: rateLimitResult.reason });
  }

  if (!isValidUrl(url)) {
    return res.status(400).json({ error: "Invalid URL format" });
  }

  const expandedUrl = await expandUrl(url);

  // Domain validation
  let domain;
  try {
    domain = new URL(expandedUrl).hostname;
  } catch {
    return res
      .status(400)
      .json({ error: "Invalid or potentially harmful URL scheme" });
  }

  const domainValidation = validateDomain(domain);
  if (!domainValidation.isValid) {
    return res.status(400).json({ error: domainValidation.reason });
  }

  // Cache check
  const cachedResult = getCachedResult(domain);
  if (cachedResult) {
    return res.status(200).json(cachedResult);
  }

  // Run all checks parallel
  const [dnsResult, typoResult, whoisResult, sslResult, phishingResult] =
    await Promise.all([
      isDnsBlacklisted(domain),
      isTypoSquatting(domain),
      getWhoisData(domain),
      hasValidCertificate(domain),
      isPhishing(expandedUrl),
    ]);

  const isMalicious =
    dnsResult || typoResult || whoisResult || !sslResult || phishingResult;

  // If the URL is malicious, block it and provide a bypass option
  if (isMalicious) {
    return res.status(403).json({
      error: "Access blocked",
      message:
        "This website is potentially malicious. Proceed at your own risk.",
      reasons: {
        dnsBlacklisted: dnsResult,
        typoSquatting: typoResult,
        newlyRegistered: whoisResult,
        invalidSSL: !sslResult,
        phishing: phishingResult,
      },
      bypassUrl: expandedUrl, 
    });
  }

  // If URL is safe, allow access
  const result = {
    isMalicious: false,
    message: "This website is safe.",
  };

  // Caching the result
  setCache(domain, result);

  res.status(200).json(result);
});

async function isDnsBlacklisted(domain) {
  for (const api of dnsBlacklistApis) {
    try {
      const response = await axios.get(`${api.url}/${domain}`, {
        headers: { "x-apikey": api.apiKey },
      });
      const stats = response.data.data.attributes.last_analysis_stats;
      return stats.malicious > 0 || stats.phishing > 0 || stats.malware > 0;
    } catch (error) {
      console.error(`DNS Blacklist API Error (${api.url}):`, error);
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
    const response = await axios.get(`${sslValidationApi}?host=${domain}`);
    return response.data.endpoints.some((endpoint) => endpoint.grade >= "A");
  } catch (error) {
    console.error("SSL Validation API Error:", error);
    return false;
  }
}

// Phishing Detection Check
async function isPhishing(url) {
  try {
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
    return stats.malicious > 0 || stats.phishing > 0;
  } catch (error) {
    console.error("Phishing Detection API Error:", error);
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

app.listen(port, () => {
  console.log(`Backend running at http://localhost:${port}`);
});
const path = require("path");

app.use(express.static(path.join(__dirname, "..", "frontend")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "..", "frontend", "index.html"));
});