import crypto from "crypto"
import fs from "fs"
import nodeforge from "node-forge"

/**
 * Available RSA padding schemes.
 * - OAEP: More secure, recommended for new implementations (RSA-OAEP with SHA-256)
 * - PKCS1: Legacy padding, kept for backward compatibility
 */
export type RSAPaddingScheme = "OAEP" | "PKCS1"

/**
 * Loads an RSA key from a file.
 * @param filePath - Path to the key file (PEM format)
 * @returns The key contents as a string
 * @throws Error if file cannot be read
 */
export function loadKey(filePath: string): string {
  try {
    if (!filePath) {
      throw new Error("File path cannot be empty")
    }
    return fs.readFileSync(filePath, "utf8")
  } catch (error) {
    throw new Error(
      `Failed to load key from ${filePath}: ${
        error instanceof Error ? error.message : String(error)
      }`,
    )
  }
}

/**
 * Encrypts text using RSA public key encryption.
 * @param text - The plaintext string to encrypt
 * @param rsaPublicKey - RSA public key (PEM format string or Buffer)
 * @param base64 - If true, returns base64 string; if false, returns Buffer (default: true)
 * @param paddingScheme - Padding scheme to use: "OAEP" (recommended) or "PKCS1" (default: "OAEP")
 * @returns Encrypted data as base64 string or Buffer
 * @throws Error if encryption fails or key is invalid
 */
export function encrypt(
  buffer: Buffer,
  rsaPublicKey: Buffer | string,
  base64: boolean = true,
  paddingScheme: RSAPaddingScheme = "OAEP",
): Buffer | string {
  // Validate inputs
  if (!buffer) {
    throw new Error("Text to encrypt cannot be empty")
  }
  if (!rsaPublicKey) {
    throw new Error("RSA public key is required")
  }

  try {
    // Determine padding based on scheme
    const padding =
      paddingScheme === "OAEP"
        ? crypto.constants.RSA_PKCS1_OAEP_PADDING
        : crypto.constants.RSA_PKCS1_PADDING

    const encryptedBuffer = crypto.publicEncrypt(
      {
        key: rsaPublicKey,
        padding,
        // Use SHA-256 for OAEP padding
        ...(paddingScheme === "OAEP" && { oaepHash: "sha256" }),
      },
      buffer,
    )

    return base64 ? encryptedBuffer.toString("base64") : encryptedBuffer
  } catch (error) {
    throw new Error(
      `RSA encryption failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
    )
  }
}

export function decrypt(
  cipherText: Buffer,
  rsaPrivateKey: string, // can be string in PEM format
  paddingScheme: RSAPaddingScheme = "OAEP",
): Buffer {
  if (paddingScheme === "PKCS1") {
    return decryptWithNodeforge(cipherText, rsaPrivateKey, paddingScheme)
  }

  // Validate inputs
  if (!cipherText) {
    throw new Error("Cipher text cannot be empty")
  }
  if (!rsaPrivateKey) {
    throw new Error("RSA private key is required")
  }

  try {
    const buffer = cipherText

    const padding =
      paddingScheme === "OAEP"
        ? crypto.constants.RSA_PKCS1_OAEP_PADDING
        : crypto.constants.RSA_PKCS1_PADDING

    const decryptedBuffer = crypto.privateDecrypt(
      {
        key: rsaPrivateKey,
        padding,
        ...(paddingScheme === "OAEP" && { oaepHash: "sha256" }),
      },
      buffer,
    )

    return decryptedBuffer as Buffer
  } catch (error) {
    throw new Error(
      `RSA decryption failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
    )
  }
}

export function decryptWithNodeforge(
  cipherText: Buffer,
  rsaPrivateKey: string, // can be string in PEM format
  paddingScheme: RSAPaddingScheme = "OAEP",
): Buffer {
  // Validate inputs
  if (!cipherText) {
    throw new Error("Cipher text cannot be empty")
  }
  if (!rsaPrivateKey) {
    throw new Error("RSA private key is required")
  }

  try {
    // Parse the private key using node-forge
    const privateKey = nodeforge.pki.privateKeyFromPem(rsaPrivateKey)

    // Convert cipherText buffer to forge-compatible format
    const encryptedBytes = nodeforge.util.createBuffer(
      cipherText.toString("binary"),
    )

    // Decrypt using node-forge
    let decrypted: string

    if (paddingScheme === "PKCS1") {
      decrypted = privateKey.decrypt(
        encryptedBytes.getBytes(),
        "RSAES-PKCS1-V1_5",
      )
    } else {
      // For OAEP padding with node-forge
      decrypted = privateKey.decrypt(encryptedBytes.getBytes(), "RSA-OAEP", {
        md: nodeforge.md.sha256.create(),
      })
    }

    // Convert result back to Buffer
    return Buffer.from(decrypted, "binary")
  } catch (error) {
    throw new Error(
      `RSA decryption with node-forge failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
    )
  }
}
