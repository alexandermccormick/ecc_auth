const ffi = require("../native");

const rawAuthToken = {
  "header": {
    iss: "example.com",
    iat: 1549061860337,
    exp: "8 m"
  },
  "body": {
    email: "chapman@example.com"
  }
}

const bob = new ffi.EccAuth("/home/alex/workspace/node/lib/ecc_auth/native/keys");

bob.sign(rawAuthToken);