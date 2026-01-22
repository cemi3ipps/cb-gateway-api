import crypto from "crypto"

export function generateSignature(inputs: {
  cu: string
  sc: string
  nonce: string
}): string {
  const { cu, sc, nonce } = inputs
  const hmac = crypto.createHmac("sha256", sc)
  hmac.update(cu + nonce)
  return `${cu} ${nonce} ${hmac.digest("base64")}`
}

export function generateNonce(length: number = 32): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
  return Array.from({ length }, () =>
    chars.charAt(Math.floor(Math.random() * chars.length)),
  ).join("")
}
