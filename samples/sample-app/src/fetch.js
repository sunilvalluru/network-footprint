// fetch.js - inbound data flows (app RECEIVES data)
import axios from "axios";

// IN: fetch a user profile from an external API
export async function getProfile(id) {
  const response = await axios.get(`https://api.acme-service.com/v1/users/${id}`);
  const userData = response.data;
  return userData;
}

// IN: download a config blob from a generic cloud storage endpoint
export async function loadRemoteConfig() {
  const res = await fetch("https://storage.googleapis.com/acme-public/config.json");
  return await res.json();
}

// IN: pull a package from the npm registry (inbound dependency download)
export async function checkLatest(pkg) {
  const res = await fetch(`https://registry.npmjs.org/${pkg}/latest`);
  return (await res.json()).version;
}
