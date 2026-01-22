import crypto from "crypto"

/**
 * Generates an HMAC-SHA256 signature for API authentication.
 * The signature is constructed by hashing the concatenation of Client ID (cu) and Nonce
 * using the Secret (sc) as the key.
 *
 * @param inputs - Object containing authentication parameters
 * @param inputs.cu - Client ID (Customer)
 * @param inputs.sc - Secret Key
 * @param inputs.nonce - A random string (Nonce)
 * @returns The formatted signature string: "Client_ID Nonce Generated_Signature"
 */
export function generateSignature(inputs: {
  cu: string
  sc: string
  nonce: string
}): string {
  const { cu, sc, nonce } = inputs
  const hmac = crypto.createHmac("sha256", sc)
  // Sign the concatenation of Client ID and Nonce
  hmac.update(cu + nonce)
  // Format: ClientID Nonce Signature
  return `${cu} ${nonce} ${hmac.digest("base64")}`
}

/**
 * Generates a random alphanumeric nonce string.
 *
 * @param length - The length of the nonce to generate (default: 32)
 * @returns A random alphanumeric string
 */
export function generateNonce(length: number = 32): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
  return Array.from({ length }, () =>
    chars.charAt(Math.floor(Math.random() * chars.length)),
  ).join("")
}
