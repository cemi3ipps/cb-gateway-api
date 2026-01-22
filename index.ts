import crypto from "crypto"

import {
  convertToPem,
  env,
  generateRandomString,
  generateSignature,
} from "./libs"
import {
  decrypt as aesDecrypt,
  encrypt as aesEncrypt,
} from "./libs/aes-256-gcm"
import { encrypt as rsaEncrypt } from "./libs/rsa"

const baseUrl =
  env.ENV !== "production"
    ? "https://va-openapi-uat2.ipps.co.th/corp-gateway/v1/gateway/"
    : "https://va-openapi.ipps.co.th/corp-gateway/v1/gateway/"

// encryption key
const rsaPublicKey = env.RSA_PUBLIC_KEY

/*
  /v1/direct_credit/transaction/account/verify
  /v1/direct_credit/transaction/account/confirm
  /account/balance/inquiry
  /account/transaction
*/

// api endpoint
const apiEndpoint = "/account/balance/inquiry"
// api payload
const reqRefNo = generateRandomString(6)
const apiPayload = { reqRefNo: reqRefNo }

// e2ee payload

const innerPayload = {
  url: apiEndpoint,
  base64: Buffer.from(JSON.stringify(apiPayload)).toString("base64"),
}

// prepare encrypted payload
const aesKey = crypto.randomBytes(32)
const rawIv = Buffer.from(reqRefNo, "utf8")

const { fullCiphertext, iv, authTag } = aesEncrypt(
  JSON.stringify(innerPayload),
  aesKey,
  rawIv,
)

// rsa encryption
const pubKey = convertToPem(rsaPublicKey)
// wrapped aes key
const wk = crypto.publicEncrypt(
  { key: pubKey, padding: crypto.constants.RSA_PKCS1_PADDING },
  aesKey,
)

const requestBody = {
  wk: wk.toString("base64"),
  payload: Buffer.from(fullCiphertext, "hex").toString("base64"),
  reqRefNo,
}

// make request

const headers = {
  "Content-Type": "application/json;charset=UTF-8",
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

if (res.respCode !== "0000") {
  throw new Error(`Endpoint Request failed: ${JSON.stringify(res, null, 2)}`)
}

// decrypt response
const decryptIv = Buffer.from(res.respRefNo, "utf8")
const ciphertext = Buffer.from(res.response, "base64")
const decrypted = aesDecrypt(
  { ciphertext, iv: decryptIv, authTag: Buffer.from(authTag, "hex") },
  aesKey,
)

console.log(decrypted)