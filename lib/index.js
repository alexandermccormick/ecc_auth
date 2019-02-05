const { EccAuth } = require("../native");

const headerConfig = {
  iss: "example.com",
  iat: 1549061860337,
  exp: "8 m"
}

const rawAuthToken = {
  "header": headerConfig,
  "body": {
    email: "chapman@example.com"
  }
}

const eccAuth = new EccAuth("/home/alex/workspace/node/lib/ecc_auth/native/keys");

const signedToken = eccAuth.sign(rawAuthToken);

const rawAuthToken2 = {
  "header": headerConfig,
  "body": {
    // email: "chapman@example.com"
    email: "dance@thedisco.com"
  }
};

const signedToken2 = eccAuth.sign(rawAuthToken2);

let pts = signedToken.split(".");
let buf = Buffer.from(pts[0], "base64");
let obj = JSON.parse(buf.toString());
obj.iss = "nope";
let _buf = Buffer.from(JSON.stringify(obj)).toString("base64");
pts[0] = _buf;
let alteredToken = pts.join(".");

console.log(true === eccAuth.verify(signedToken));
console.log(false === eccAuth.verify(alteredToken));