const ffi = require("../native");

// const authToken = {
//   "header": {
//     iss: "example.com",
//     iat: 1547611539072,
//     exp: "30 d"
//   },
//   "body": {
//     email: "chapman@example.com"
//   }
// }

// const someObj = EccAuth.initEccAuth(authToken);

const bob = new ffi.EccAuth("/home/alex/workspace/node/lib/ecc_auth/native/keys");

bob.sign();