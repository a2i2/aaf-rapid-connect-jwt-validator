import should from "should";
import { encode as encodeJWT } from "jwt-simple";
import validateJWT from "../lib";

const appUrl = "https://example.com";
const jwtSecret = "secret";

describe("aaf-rapid-connect-jwt-validator", () => {
  it("should return user attributes when JWT is valid", () => {
    let jwt = {
      iss: "https://rapid.aaf.edu.au",
      aud: appUrl,
      nbf: Math.round(Date.now() / 1000) - 1000,
      exp: Math.round(Date.now() / 1000) + 1000,
      jti: "abc123",
      "https://aaf.edu.au/attributes": {
        attr1: 1,
        attr2: 2
      }
    };
    let assertion = encodeJWT(jwt, jwtSecret);
    let userAttributes = validateJWT(assertion, appUrl, jwtSecret);
    userAttributes.should.be.an.Object().and.have.keys("attr1", "attr2");
    userAttributes.attr1.should.be.a.Number().and.equal(1);
    userAttributes.attr2.should.be.a.Number().and.equal(2);
  });
});
