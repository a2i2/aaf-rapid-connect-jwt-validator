import { decode as decodeJWT } from "jwt-simple";

export default function(assertion, appUrl, jwtSecret) {
  if (!assertion) throw new Error(`Parameter "assertion" is undefined.`);
  if (!appUrl) throw new Error(`Parameter "appUrl" is undefined.`);

  let jwt;
  try {
    jwt = decodeJWT(assertion, jwtSecret, !jwtSecret);
  } catch (error) {
    throw new Error("Failed to decode signed JWT.");
  }

  if (jwt.iss !== "https://rapid.aaf.edu.au") {
    throw new Error("Invalid JWT issuer.");
  } else if (jwt.aud !== appUrl) {
    throw new Error("Invalid JWT audience.");
  } else if (jwt.nbf > Math.round(Date.now() / 1000)) {
    throw new Error("Invalid JWT start time.");
  } else if (jwt.exp <= Math.round(Date.now() / 1000)) {
    throw new Error("Invalid JWT end time.");
  }

  return jwt["https://aaf.edu.au/attributes"];
}
