"use strict";

const UV_SW = "/uv/sw.js";
const swAllowedHostnames = ["localhost", "127.0.0.1"];

async function registerSW() {
  if (!navigator.serviceWorker) {
    if (
      location.protocol !== "https:" &&
      !swAllowedHostnames.includes(location.hostname)
    ) throw new Error("Service workers require HTTPS.");
    throw new Error("Your browser doesn't support service workers.");
  }

  // Clear ALL old service worker registrations (scramjet etc)
  const existing = await navigator.serviceWorker.getRegistrations();
  for (const reg of existing) {
    const swUrl = reg.active?.scriptURL || reg.installing?.scriptURL || reg.waiting?.scriptURL || "";
    if (!swUrl.endsWith(UV_SW)) {
      console.log("[Kairo] Removing old SW:", swUrl);
      await reg.unregister();
    }
  }

  // Register UV service worker
  await navigator.serviceWorker.register(UV_SW, { scope: "/uv/" });
}
