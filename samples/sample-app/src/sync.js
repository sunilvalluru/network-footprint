// sync.js - bidirectional data flows (app SENDS and RECEIVES)
import axios from "axios";

// BOTH: upload a document AND read back the processed result
export async function processDocument(fileBuffer) {
  const form = new FormData();
  form.append("file", fileBuffer);
  const result = await axios.post("https://api.docparser.io/process", form); // send
  const processed = result.data;                                             // receive
  return processed.downloadUrl;
}

// BOTH: a websocket connection streams data in and out continuously
export function openStream() {
  const ws = new WebSocket("wss://stream.acme-realtime.com/socket");
  ws.onmessage = (m) => handle(m.data);        // inbound
  ws.send(JSON.stringify({ subscribe: "ticks" })); // outbound
  return ws;
}

function handle(_) {}
