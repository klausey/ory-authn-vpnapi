import { Application, Router } from "https://deno.land/x/oak/mod.ts";

const app = new Application();
const router = new Router();

// Define the bearer token for authentication
const BEARER_TOKEN = Deno.env.get("BEARER_TOKEN");
if (!BEARER_TOKEN) {
  throw new Error("Bearer token is not set");
}
const VPNAPIIO_API_KEY = Deno.env.get("VPNAPIIO_API_KEY");
if (!VPNAPIIO_API_KEY) {
  throw new Error("VPNAPIIO_API_KEY is not set");
}

router.post("/vpncheck", async (context) => {
  // Check for bearer token authentication
  const authHeader = context.request.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    context.response.status = 401;
    context.response.body = { error: "Unauthorized" };
    return;
  }

  const providedToken = authHeader.split("Bearer ")[1];
  if (providedToken !== BEARER_TOKEN) {
    context.response.status = 401;
    context.response.body = { error: "Unauthorized" };
    return;
  }

  // Parse the JSON payload and extract the IP address
  const body = await context.request.body();
  if (!body.type || body.type !== "json") {
    context.response.status = 400;
    context.response.body = { error: "Invalid Content-Type" };
    return;
  }

  const { ip_address } = await body.value;
  if (!ip_address) {
    context.response.status = 400;
    context.response.body = { error: "Missing IP address" };
    return;
  }

  // Call vpnapi.io to check the IP address
  let vpnResult;
  try {
    vpnResult = await checkVpn(ip_address);
  } catch (error) {
    context.response.status = 200;
    context.response.body = {
      warning: "Unable to check VPN",
      details: error.message,
    };
    return;
  }

  // Check the response from vpnapi.io
  if (vpnResult?.error === "Blocked") {
    context.response.status = 400;
    context.response.body = { error: "Request blocked: Blocked" };
    return;
  }

  const securityInfo = vpnResult?.security;
  if (securityInfo?.vpn === true) {
    context.response.status = 400;
    context.response.body = { error: "Request blocked: VPN" };
    return;
  }

  if (securityInfo?.tor === true) {
    context.response.status = 400;
    context.response.body = { error: "Request blocked: Tor" };
    return;
  }

  if (
    vpnResult?.location?.country_code === "RU"
  ) {
    context.response.status = 400;
    context.response.body = { error: "Request blocked: Geolocation" };
    return;
  }

  // Return the result as success or error details
  context.response.status = 200;
  context.response.body = vpnResult || {};
});

async function checkVpn(ipAddress) {
  // Implement the logic to call vpnapi.io and retrieve the result
  // You can use libraries like axios or fetch for making HTTP requests
  // Return the response as an object

  const response = await fetch(
    `https://vpnapi.io/api/${ipAddress}?key=${VPNAPIIO_API_KEY}`,
    { timeout: 1500 },
  );
  if (!response.ok) {
    throw new Error(`vpnapi.io returned ${response.status}`);
  }

  return await response.json();
}

app.use(router.routes());
app.use(router.allowedMethods());

await app.listen({ port: 5001 });