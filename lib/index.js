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

// console.log("equal signature: ", (signedToken === signedToken2));
// console.log("signedToken:\n", signedToken);
// console.log("signedToken2:\n", signedToken2);

console.log(eccAuth.verify(signedToken));