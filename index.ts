import { createId } from "@paralleldrive/cuid2"
import crypto from "crypto"

import {
  convertToPem,
  env,
  generateRandomString,
  generateSignature,
} from "./libs"
import {
  encrypt as aesEncrypt,
  decryptFullCiphertext,
} from "./libs/aes-256-gcm"

const baseUrl =
  env.NODE_ENV !== "production"
    ? "https://va-openapi-uat2.ipps.co.th/corp-gateway/v1/gateway/"
    : "https://va-openapi.ipps.co.th/corp-gateway/v1/gateway/"

// encryption key
const rsaPublicKey = env.RSA_PUBLIC_KEY

/*
  example endpoints:
  /v1/direct_credit/transaction/account/verify
  /v1/direct_credit/transaction/account/confirm
  
  /account/balance/inquiry
  /account/transaction

  /v1/direct_credit/transaction/payee/verify
  /v1/direct_credit/transaction/payee/confirm
  /v1/direct_credit/payee/inquiry
  /v1/direct_credit/payee/add
  /v1/direct_credit/payee/deregister
*/

// api endpoint
const apiEndpoint = "/v1/direct_credit/transaction/account/verify"
// api payload
const reqRefNo = generateRandomString(6)

// const apiPayload = { reqRefNo: reqRefNo }
const apiPayload = {
  toBankBicCode: env.TO_BANK_BIC,
  toAccountNo: env.TO_BANK_ACC,
  trnAmount: 15,
  clientRequestNo: createId().slice(0, 20), // max 20 characters allowed
  // referenceMessageOut: null, // optional nullable string
  reqRefNo: reqRefNo,
}

console.log("\nAPI Body: ", apiPayload)

// e2ee payload
// The inner payload contains the target API endpoint and the base64-encoded business payload.
// This ensures that the gateway knows where to route the request after decryption.
const innerPayload = {
  url: apiEndpoint,
  base64: Buffer.from(JSON.stringify(apiPayload)).toString("base64"),
}

console.log("\nInner Payload: ", innerPayload)

// prepare encrypted payload
// 1. Generate a random 32-byte AES key for this session/request.
const aesKey = crypto.randomBytes(32)
// 2. Use the request reference number (reqRefNo) as the Initialization Vector (IV) source.
const rawIv = Buffer.from(reqRefNo, "utf8")

// 3. Encrypt the inner payload using AES-256-GCM.
const { fullCiphertext, iv, authTag } = aesEncrypt(
  JSON.stringify(innerPayload),
  aesKey,
  rawIv,
)

// rsa encryption
// 4. Encrypt the AES key using the Gateway's RSA Public Key.
// This is known as "Key Wrapping". Only the Gateway (holding the Private Key) can decrypt this to get the AES key.
const pubKey = convertToPem(rsaPublicKey)
// wrapped aes key
const wk = crypto.publicEncrypt(
  { key: pubKey, padding: crypto.constants.RSA_PKCS1_PADDING },
  aesKey,
)

// 5. Construct the final request body.
// - wk: The RSA-encrypted AES key (Base64).
// - payload: The AES-encrypted data (Base64).
// - reqRefNo: The reference number used for tracking and IV generation.
const requestBody = {
  wk: wk.toString("base64"),
  payload: Buffer.from(fullCiphertext, "hex").toString("base64"),
  reqRefNo,
}

console.log("\nFinal Request Body: ", requestBody)

// make request
// Headers include authentication and integrity checks.
const headers = {
  "Content-Type": "application/json;charset=UTF-8",
  // X-Signature: HMAC-SHA256 signature of Client ID, Secret, and Nonce.
  "X-Signature": generateSignature({
    cu: env.CB_CLIENT_ID,
    sc: env.CB_SECRET,
    nonce: generateRandomString(32),
  }),
  "X-Token": env.CB_ACCESS_TOKEN,
  "X-ClientName": env.CB_CLIENT,
}

const response = await fetch(baseUrl, {
  method: "POST",
  headers: headers,
  body: JSON.stringify(requestBody),
})

if (!response.ok) {
  throw new Error(`Gateway request failed: ${response.status}`)
}

const res = (await response.json()) as {
  respCode: string
  respDesc: string
  reqRefNo: string
  respRefNo: string
  statusCode: number
  response: string
}

// Check for business logic errors from the gateway
if (res.respCode !== "0000") {
  throw new Error(`Endpoint Request failed: ${JSON.stringify(res, null, 2)}`)
}

console.log("\nResponse: ", res)

// Decrypt the response
// The gateway responds with an encrypted payload (res.response).
// We decrypt it using:
// 1. The SAME AES key that we generated and sent in the request (session key).
// 2. The response reference number (respRefNo) as the IV.
const rawResponse = Buffer.from(res.response, "base64")
const decryptIv = Buffer.from(res.respRefNo, "utf8")

const decrypted = decryptFullCiphertext(rawResponse, decryptIv, aesKey)

console.log("\nDecrypted response: ", JSON.parse(decrypted.toString("utf8")))
