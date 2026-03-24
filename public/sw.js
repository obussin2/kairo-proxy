// 1. Import the BareMux engine so the SW can actually connect to the internet
importScripts("/baremux/bare.cjs");
// 2. Import the Scramjet worker (NOT all.js)
importScripts("/scram/scramjet.worker.js");

const { ScramjetServiceWorker } = $scramjetLoadWorker();
const scramjet = new ScramjetServiceWorker();

async function handleRequest(event) {
  await scramjet.loadConfig();
  if (scramjet.route(event)) {
    return scramjet.fetch(event);
  }
  return fetch(event.request);
}

self.addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event));
});
