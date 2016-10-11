import should from "should";
import { encode as encodeJWT } from "jwt-simple";
import validateJWT from "../lib";

const appUrl = "https://example.com";
const jwtSecret = "secret";

describe("aaf-rapid-connect-jwt-validator", () => {
  it("should return a Promise resolved with user attributes", () => {
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
    let promise = validateJWT(assertion, appUrl, jwtSecret, () => {}, () => {});

    promise.should.be.a.Promise();

    return promise.then(attrs => {
      attrs.should.be.an.Object().and.have.keys("attr1", "attr2");
      attrs.attr1.should.be.a.Number().and.equal(1);
      attrs.attr2.should.be.a.Number().and.equal(2);
    });
  });
});
