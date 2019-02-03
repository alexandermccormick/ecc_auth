const { EccAuth } = require("../native");

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

const bob = new EccAuth("/home/alex/workspace/node/lib/ecc_auth/native/keys");

const origToken = bob.sign(rawAuthToken);

// console.log("from js\n", origToken);

const rawAuthToken2 = {
  "header": {
    iss: "example.com",
    iat: 1549061860337,
    exp: "8 m"
  },
  "body": {
    email: "chapman@example.com"
  }
};

const anotherToken = bob.sign(rawAuthToken2);
// console.log("from js\n", anotherToken);

// console.log("equal signature: ", (origToken.signature === anotherToken.signature));
// console.log("equal arr value: ", (origToken.header == anotherToken.header));
console.log("origToken:\n", origToken);
console.log("anotherToken:\n", anotherToken);
// for( let i = origToken.length - 1; i >= 0; i--) {
//   if (origToken[i] === anotherToken[i]) {
//     continue;
//   } else {
//     console.log("**** Difference!!! ****");
//     break;
//   }
// }