import { decode as decodeJWT } from "jwt-simple";

export default function(options = {}) {
  return new Promise((resolve, reject) => {
    let { assertion, appUrl, jwtSecret, findToken, storeToken } = options;

    if (!assertion) throw new Error(`Option "assertion" is undefined.`);
    if (!appUrl) throw new Error(`Option "appUrl" is undefined.`);
    if (!jwtSecret) throw new Error(`Option "jwtSecret" is undefined.`);
    if (!findToken) throw new Error(`Option "findToken" is undefined.`);
    if (!storeToken) throw new Error(`Option "storeToken" is undefined.`);

    let jwt = (() => {
      try {
        return decodeJWT(assertion, jwtSecret);
      } catch (error) {
        throw new Error("Failed to decode signed JWT.");
      }
    })();

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
      if (found) throw new Error("Duplicate JWT identifier."); // The same token cannot be used twice.
      return storeToken(jwt.jti);
    })
    .then(() => jwt["https://aaf.edu.au/attributes"])
    .then(resolve)
    .catch(reject);
  });
}
