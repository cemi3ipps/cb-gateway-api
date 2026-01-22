import crypto from "crypto"

/**
 * Validates if a string is a valid PEM (Privacy-Enhanced Mail) format.
 * Checks for matching "BEGIN" and "END" headers/footers.
 *
 * Supported formats include but are not limited to:
 * - PUBLIC KEY
 * - PRIVATE KEY
 * - RSA PRIVATE KEY
 * - CERTIFICATE
 *
 * @param key - The string to validate
 * @returns boolean - True if the string follows PEM format
 */
export function isValidPEM(key: string): boolean {
  if (!key || typeof key !== "string") {
    return false
  }

  const trimmedKey = key.trim()

  // Regex breakdown:
  // ^-----BEGIN ([A-Z\s]+)-----  -> Matches start header and captures the label (e.g. "PUBLIC KEY")
  // [\s\S]+                      -> Matches any content (body), including newlines
  // -----END \1-----$            -> Matches end footer, ensuring the label matches the captured group \1
  const pemPattern = /^-----BEGIN ([A-Z\s]+)-----[\s\S]+-----END \1-----$/

  return pemPattern.test(trimmedKey)
}

/**
 * Generates a traditional hex-based request ID.
 *
 * @param length - The length of the ID to generate (default: 6)
 * @param isUpper - Whether to return uppercase hex (default: true)
 * @returns A random hex string
 */
export function getTraditionalRequestId(
  length: number = 6,
  isUpper: boolean = true,
): string {
  const randByte = crypto.randomBytes(length)
  const reqId = randByte.toString("hex").slice(-length)
  return isUpper ? reqId.toUpperCase() : reqId
}

/**
 * Generates a request ID safe for Corporate Bank usage (base64url based).
 * Strips special characters like '-', '/', and '_' to ensure compatibility.
 *
 * @param length - The length of the ID to generate (default: 6)
 * @returns A random URL-safe string
 */
export function getCbRequestId(length: number = 6): string {
  const randByte = crypto.randomBytes(length)
  let reqId = randByte.toString("base64url")
  // strip - / _
  reqId = reqId.replace(/[-/_]/g, "")
  return reqId.slice(-length)
}

/**
 * Converts a raw base64 key string into PEM format.
 * Wraps the base64 string at 64 characters per line and adds appropriate headers/footers.
 *
 * @param base64 - The raw base64 key string
 * @param type - The key type: "PUBLIC_KEY" or "PRIVATE_KEY" (default: "PUBLIC_KEY")
 * @returns The key in PEM format
 */
export function convertToPem(
  base64: string,
  type: "PUBLIC_KEY" | "PRIVATE_KEY" = "PUBLIC_KEY",
): string {
  const wrappedBase64 = base64.match(/.{1,64}/g)?.join("\n") || base64
  if (type === "PUBLIC_KEY") {
    return `-----BEGIN PUBLIC KEY-----\n${wrappedBase64}\n-----END PUBLIC KEY-----`
  }
  return `-----BEGIN RSA PRIVATE KEY-----\n${wrappedBase64}\n-----END RSA PRIVATE KEY-----`
}

/**
 * Derives an RSA public key from a private key.
 *
 * @param privateKeyPem - The RSA private key in PEM format
 * @returns The derived public key in PEM format (SPKI format)
 * @throws Error if the private key is invalid or cannot be parsed
 *
 * @example
 * ```ts
 * const privateKey = `-----BEGIN RSA PRIVATE KEY-----
 * MIIEpAIBAAKCAQEA...`
 * const publicKey = deriveRsaPublicKey(privateKey)
 * console.log(publicKey) // -----BEGIN PUBLIC KEY-----...
 * ```
 */
export function deriveRsaPublicKey(privateKeyPem: string): string {
  if (!isValidPEM(privateKeyPem)) {
    throw new Error("Invalid PEM format for private key")
  }

  try {
    // Create a private key object from the PEM string
    const privateKey = crypto.createPrivateKey({
      key: privateKeyPem,
      format: "pem",
    })

    // Derive the public key from the private key
    const publicKey = crypto.createPublicKey(privateKey)

    // Export the public key in PEM format (SPKI format)
    return publicKey.export({
      type: "spki",
      format: "pem",
    }) as string
  } catch (error) {
    throw new Error(
      `Failed to derive public key from private key: ${error instanceof Error ? error.message : String(error)}`,
    )
  }
}

/**
 * Generates a random uppercase hex string.
 *
 * @param length - The length of the string to generate (default: 8)
 * @returns A random uppercase hex string
 */
export function generateRandomString(length: number = 8): string {
  return crypto
    .randomBytes(length)
    .toString("hex")
    .slice(0, length)
    .toLocaleUpperCase()
}
