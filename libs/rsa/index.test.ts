import { beforeAll, describe, expect, it } from "bun:test"
import crypto from "crypto"

import {
  decryptWithNodeforge,
  encrypt,
  loadKey,
} from "./index"

describe("decryptWithNodeforge", () => {
  let testPrivateKey: string
  let testPublicKey: string

  beforeAll(() => {
    // Load test keys from the data directory
    testPrivateKey = loadKey("src/data/key.pem")
    testPublicKey = loadKey("src/data/pub.pem")
  })

  describe("PKCS1 padding tests", () => {
    it("should decrypt data encrypted with PKCS1 padding", () => {
      const originalText = "Hello, World! This is a test message."
      const buffer = Buffer.from(originalText, "utf8")

      // Encrypt using PKCS1 padding with Node.js crypto
      const encrypted = encrypt(buffer, testPublicKey, false, "PKCS1") as Buffer

      // Decrypt using node-forge
      const decrypted = decryptWithNodeforge(encrypted, testPrivateKey, "PKCS1")

      expect(decrypted.toString("utf8")).toBe(originalText)
    })

    it("should handle moderately sized data with PKCS1 padding", () => {
      const originalText = JSON.stringify({
        service: "TRN_NOTI",
        accountNo: "120111220003608",
        trnCode: "TUP_PXY",
        amount: 1000,
      })
      const buffer = Buffer.from(originalText, "utf8")

      // Encrypt using PKCS1 padding
      const encrypted = encrypt(buffer, testPublicKey, false, "PKCS1") as Buffer

      // Decrypt using node-forge
      const decrypted = decryptWithNodeforge(encrypted, testPrivateKey, "PKCS1")

      expect(decrypted.toString("utf8")).toBe(originalText)
    })
  })

  describe("OAEP padding tests", () => {
    it("should decrypt data encrypted with OAEP padding", () => {
      const originalText = "Hello, World! This is a test with OAEP padding."
      const buffer = Buffer.from(originalText, "utf8")

      // Encrypt using OAEP padding with Node.js crypto
      const encrypted = encrypt(buffer, testPublicKey, false, "OAEP") as Buffer

      // Decrypt using node-forge
      const decrypted = decryptWithNodeforge(encrypted, testPrivateKey, "OAEP")

      expect(decrypted.toString("utf8")).toBe(originalText)
    })

    it("should handle JSON data with OAEP padding", () => {
      const jsonData = {
        id: "123",
        amt: 2500,
      }
      const originalText = JSON.stringify(jsonData)
      const buffer = Buffer.from(originalText, "utf8")

      // Encrypt using OAEP padding
      const encrypted = encrypt(buffer, testPublicKey, false, "OAEP") as Buffer

      // Decrypt using node-forge
      const decrypted = decryptWithNodeforge(encrypted, testPrivateKey, "OAEP")

      expect(decrypted.toString("utf8")).toBe(originalText)
    })
  })

  describe("Error handling tests", () => {
    it("should throw error when cipher text is empty", () => {
      expect(() => {
        decryptWithNodeforge(Buffer.alloc(0), testPrivateKey, "PKCS1")
      }).toThrow()
    })

    it("should throw error when private key is empty", () => {
      const buffer = Buffer.from("test", "utf8")
      expect(() => {
        decryptWithNodeforge(buffer, "", "PKCS1")
      }).toThrow("RSA private key is required")
    })

    it("should throw error when private key is null", () => {
      const buffer = Buffer.from("test", "utf8")
      expect(() => {
        decryptWithNodeforge(buffer, null as any, "PKCS1")
      }).toThrow("RSA private key is required")
    })

    it("should throw error with invalid cipher text", () => {
      const invalidCipher = Buffer.from("invalid_encrypted_data", "utf8")
      expect(() => {
        decryptWithNodeforge(invalidCipher, testPrivateKey, "PKCS1")
      }).toThrow("RSA decryption with node-forge failed")
    })

    it("should throw error with invalid private key", () => {
      const buffer = Buffer.from("test", "utf8")
      const invalidKey =
        "-----BEGIN RSA PRIVATE KEY-----\nINVALID_KEY_DATA\n-----END RSA PRIVATE KEY-----"
      expect(() => {
        decryptWithNodeforge(buffer, invalidKey, "PKCS1")
      }).toThrow("RSA decryption with node-forge failed")
    })
  })

  describe("Binary data tests", () => {
    it("should handle binary data correctly", () => {
      // Create binary data (e.g., an AES key)
      const binaryData = crypto.randomBytes(32)

      // Encrypt using PKCS1 padding
      const encrypted = encrypt(
        binaryData,
        testPublicKey,
        false,
        "PKCS1",
      ) as Buffer

      // Decrypt using node-forge
      const decrypted = decryptWithNodeforge(encrypted, testPrivateKey, "PKCS1")

      expect(decrypted).toEqual(binaryData)
    })

    it("should handle different buffer encodings", () => {
      const originalText = "Test with special characters: ñáéíóú 中文 🚀"
      const utf8Buffer = Buffer.from(originalText, "utf8")
      const hexBuffer = Buffer.from(originalText, "hex") // This will be different, just testing buffer handling

      // Test UTF8 buffer
      const encrypted1 = encrypt(
        utf8Buffer,
        testPublicKey,
        false,
        "PKCS1",
      ) as Buffer
      const decrypted1 = decryptWithNodeforge(
        encrypted1,
        testPrivateKey,
        "PKCS1",
      )
      expect(decrypted1.toString("utf8")).toBe(originalText)

      // Test that we can handle any buffer (even if it doesn't decode as text)
      const encrypted2 = encrypt(
        hexBuffer,
        testPublicKey,
        false,
        "PKCS1",
      ) as Buffer
      const decrypted2 = decryptWithNodeforge(
        encrypted2,
        testPrivateKey,
        "PKCS1",
      )
      expect(decrypted2).toEqual(hexBuffer)
    })
  })

  describe("Round-trip compatibility tests", () => {
    it("should be compatible with encryption from Node.js crypto for PKCS1", () => {
      const testCases = [
        "Short message",
        "Medium length with numbers 12345",
        JSON.stringify({ test: "object", num: 1 }),
      ]

      testCases.forEach((testCase) => {
        const buffer = Buffer.from(testCase, "utf8")

        // Encrypt with Node.js crypto
        const encrypted = encrypt(
          buffer,
          testPublicKey,
          false,
          "PKCS1",
        ) as Buffer

        // Decrypt with node-forge
        const decrypted = decryptWithNodeforge(
          encrypted,
          testPrivateKey,
          "PKCS1",
        )

        expect(decrypted.toString("utf8")).toBe(testCase)
      })
    })

    it("should be compatible with encryption from Node.js crypto for OAEP", () => {
      const testCases = [
        "OAEP test message",
        "Another test with unicode: héllo wörld 🌍",
        JSON.stringify({ api: "webhook", version: "1.0", secure: true }),
      ]

      testCases.forEach((testCase, index) => {
        const buffer = Buffer.from(testCase, "utf8")

        // Encrypt with Node.js crypto
        const encrypted = encrypt(
          buffer,
          testPublicKey,
          false,
          "OAEP",
        ) as Buffer

        // Decrypt with node-forge
        const decrypted = decryptWithNodeforge(
          encrypted,
          testPrivateKey,
          "OAEP",
        )

        expect(decrypted.toString("utf8")).toBe(testCase)
      })
    })
  })
})
