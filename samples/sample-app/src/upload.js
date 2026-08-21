// upload.js - outbound data flows (app SENDS data)
import axios from "axios";
import AWS from "aws-sdk";

const CONFIG = require("../config/config.json");

// OUT: POST a report payload to a third-party API endpoint
export async function submitReport(report) {
  const payload = JSON.stringify({ report, ts: Date.now() });
  // uploadUrl is bound in config/config.json -> service.uploadUrl
  const res = await axios.post(CONFIG.service.uploadUrl, payload, {
    headers: { "Content-Type": "application/json" },
  });
  return res.data.id;
}

// OUT: upload a file to a SPECIFIC S3 bucket (fully-qualified cloud endpoint)
export async function uploadArtifact(buffer) {
  const s3 = new AWS.S3({ endpoint: "https://acme-artifacts.s3.us-east-2.amazonaws.com" });
  await s3.putObject({
    Bucket: "acme-artifacts",
    Key: `builds/${Date.now()}.zip`,
    Body: buffer,
  }).promise();
}

// OUT: push events to an analytics/telemetry collector
export async function track(event) {
  const dataToSend = { event, app: "sample-app" };
  await fetch("https://collector.mixpanel.com/track", {
    method: "POST",
    body: JSON.stringify(dataToSend),
  });
}
