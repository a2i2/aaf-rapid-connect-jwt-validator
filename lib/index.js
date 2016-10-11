import { decode as decodeJWT } from "jwt-simple";

export default function(options = {}) {
  return new Promise((resolve, reject) => {
    let { assertion, appUrl, jwtSecret, findToken, storeToken } = options;

    if (!assertion) throw new Error(`Parameter "assertion" is undefined.`);
    if (!appUrl) throw new Error(`Parameter "appUrl" is undefined.`);
    if (!jwtSecret) throw new Error(`Parameter "jwtSecret" is undefined.`);
    if (!findToken) throw new Error(`Parameter "findToken" is undefined.`);
    if (!storeToken) throw new Error(`Parameter "storeToken" is undefined.`);

    let jwt;
    try {
      jwt = decodeJWT(assertion, jwtSecret);
    } catch (error) {
      throw new Error("Failed to decode signed JWT.");
    }

    if (jwt.iss !== "https://rapid.aaf.edu.au") {
      throw new Error("Invalid JWT issuer.");
    }

    if (jwt.aud !== appUrl) {
      throw new Error("Invalid JWT audience.");
    }

    if (jwt.nbf > Math.round(Date.now() / 1000)) {
      throw new Error("Invalid JWT start time.");
    }

    if (jwt.exp <= Math.round(Date.now() / 1000)) {
      throw new Error("Invalid JWT end time.");
    }

    Promise.resolve(findToken(jwt.jti))
    .then(found => {
      if (found) throw new Error("Invalid JWT identifier."); // The same token cannot be used twice.
      return storeToken(jwt.jti);
    })
    .then(() => jwt["https://aaf.edu.au/attributes"])
    .then(resolve)
    .catch(reject);
  });
}
