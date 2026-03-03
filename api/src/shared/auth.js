Perfect! I found the issue. Your validateToken function is not checking for the access_as_user scope!
The token is being validated but the scope check is missing. Here's the fix:
javascriptconst jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");

const tenantId = process.env.AZURE_AD_TENANT_ID;
const clientId = process.env.AZURE_AD_CLIENT_ID;

console.log("Auth Config:", { tenantId, clientId }); // Debug log

const jwks = jwksClient({
  jwksUri: `https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`,
  cache: true,
  rateLimit: true,
});

function getSigningKey(header, callback) {
  jwks.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err);
    callback(null, key.getPublicKey());
  });
}

async function validateToken(request) {
  const authHeader = request.headers.get("authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    console.error("❌ No Bearer token");
    return null;
  }

  const token = authHeader.substring(7);

  return new Promise((resolve, reject) => {
    jwt.verify(
      token,
      getSigningKey,
      {
        audience: clientId,
        issuer: `https://login.microsoftonline.com/${tenantId}/v2.0`,
        algorithms: ["RS256"],
      },
      (err, decoded) => {
        if (err) {
          console.error("❌ Token verification failed:", err.message);
          resolve(null);
        } else {
          // ✅ NEW: Check for the access_as_user scope
          const scopes = (decoded.scp || '').split(' ');
          console.log("Token scopes:", scopes);
          
          if (!scopes.includes('access_as_user')) {
            console.error("❌ Token missing 'access_as_user' scope");
            resolve(null);
          } else {
            console.log("✅ Token verified successfully");
            resolve(decoded);
          }
        }
      }
    );
  });
}

function requireAuth(handler) {
  return async (request, context) => {
    const user = await validateToken(request);
    if (!user) {
      return { status: 401, jsonBody: { error: "Unauthorized" } };
    }
    request.user = user;
    return handler(request, context);
  };
}

module.exports = { validateToken, requireAuth };
