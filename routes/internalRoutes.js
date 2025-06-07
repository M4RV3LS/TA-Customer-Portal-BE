// customer-portal/backend/routes/internalRoutes.js
const express = require("express");
const router = express.Router();
const connection = require("../dbConnection");
const { ethers } = require("ethers");
const KYCArtifact = require("../abi/KycRegistryV3.json");
const util = require("util");
const queryAsync = util.promisify(connection.query).bind(connection);
const { aesEncrypt } = require("../utils/cryptoUtils"); // Use the existing util
const crypto = require("crypto");

// --- Bank Authentication Middleware (Simplified API Key Check) ---
// In production, use a more robust method like OAuth 2.0 client credentials or mTLS.
const VALID_BANK_API_KEYS_TO_ID = {
  [process.env.API_KEY_FOR_BANK_A]: "BANK_A",
  [process.env.API_KEY_FOR_BANK_B]: "BANK_B",
  // Add more banks here
};

function authenticateBankRequest(req, res, next) {
  const apiKey = req.headers["x-api-key"];
  const bankIdentifier = VALID_BANK_API_KEYS_TO_ID[apiKey];

  if (bankIdentifier) {
    req.requestingBankId = bankIdentifier; // e.g., "BANK_A"
    // Fetch the on-chain address for this bank identifier from .env
    req.requestingBankAddress = process.env[`${bankIdentifier}_SIGNER_ADDRESS`];

    if (!req.requestingBankAddress) {
      console.error(
        `[INTERNAL AUTH] Signer address for ${bankIdentifier} is not configured in Customer Portal .env.`
      );
      return res.status(500).json({
        error: "Internal server configuration error (bank address mapping).",
      });
    }
    console.log(
      `[INTERNAL AUTH] Authenticated bank: ${req.requestingBankId} with address ${req.requestingBankAddress}`
    );
    return next();
  }
  console.warn(
    "[INTERNAL AUTH] Authentication failed: Invalid or missing X-API-Key header."
  );
  return res
    .status(401)
    .json({ error: "Bank authentication failed: Invalid or missing API key." });
}
// --- End Bank Authentication Middleware ---

// Ethereum Setup for Customer Portal Backend (to check banks_ids on KycRegistry)
let kycContractInstance;
try {
  const rpcUrl = process.env.RPC_URL_FOR_CUSTOMER_PORTAL;
  const contractAddress = process.env.KYC_REGISTRY_ADDRESS_FOR_CUSTOMER_PORTAL;
  if (!rpcUrl || !contractAddress) {
    throw new Error(
      "RPC_URL_FOR_CUSTOMER_PORTAL or KYC_REGISTRY_ADDRESS_FOR_CUSTOMER_PORTAL is not set in Customer Portal .env"
    );
  }
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  kycContractInstance = new ethers.Contract(
    contractAddress,
    KYCArtifact.abi,
    provider
  );
  console.log(
    `[CP Internal] Connected to KYC Registry contract at ${contractAddress} via ${rpcUrl}`
  );
} catch (e) {
  console.error(
    "[CP Internal] FATAL: Could not initialize ethers contract for KYC Registry.",
    e.message
  );
  // You might want to prevent the app from starting or handle this more gracefully
  kycContractInstance = null;
}

router.post(
  "/request-decryption-key",
  authenticateBankRequest,
  async (req, res) => {
    const { userId } = req.body; // This is the client_id/user_id from customer's perspective
    const requestingBankId = req.requestingBankId; // e.g., "BANK_A"
    const requestingBankAddress = req.requestingBankAddress; // On-chain address of the bank making the request

    if (!userId || typeof userId !== "number") {
      return res
        .status(400)
        .json({ error: "Missing or invalid 'userId' in request body." });
    }
    if (!kycContractInstance) {
      console.error("[REQUEST-KEY] KYC Contract instance not available.");
      return res.status(500).json({
        error: "Internal server error: Blockchain service unavailable.",
      });
    }

    try {
      // 1. Verify on-chain that requestingBankAddress is in banks_ids for this userId
      console.log(
        `[REQUEST-KEY] Verifying if bank ${requestingBankAddress} is a participant for user ${userId} on-chain.`
      );
      const participatingBanksOnChain =
        await kycContractInstance.getParticipatingBanks(userId);
      const isAuthorizedOnChain = participatingBanksOnChain.some(
        (addr) => addr.toLowerCase() === requestingBankAddress.toLowerCase()
      );

      if (!isAuthorizedOnChain) {
        console.warn(
          `[REQUEST-KEY] Authorization DENIED: Bank <span class="math-inline">\{requestingBankId\} \(</span>{requestingBankAddress}) is NOT in banks_ids for user ${userId}.`
        );
        return res.status(403).json({
          error:
            "Requesting bank is not authorized for this user's KYC data based on on-chain records (not a paying participant).",
        });
      }
      console.log(
        `[REQUEST-KEY] Authorization GRANTED: Bank <span class="math-inline">\{requestingBankId\} \(</span>{requestingBankAddress}) is in banks_ids for user ${userId}.`
      );

      // 2. Fetch the decrypt_key from user_profiles
      const [userProfile] = await new Promise((resolve, reject) =>
        connection.query(
          "SELECT decrypt_key FROM user_profiles WHERE user_id = ?",
          [userId],
          (err, results) => (err ? reject(err) : resolve(results))
        )
      );

      if (!userProfile || !userProfile.decrypt_key) {
        console.error(
          `[REQUEST-KEY] No decrypt_key found for user ${userId} in customer_portal.user_profiles database.`
        );
        return res.status(404).json({
          error:
            "Decryption key not found for the specified user in Customer Portal.",
        });
      }

      console.log(
        `[REQUEST-KEY] Successfully retrieved decrypt_key for user ${userId} to be provided to bank ${requestingBankId}.`
      );
      console.log(
        `[CP - /internal/request-key] For userId: ${userId}, returning decryptKey: ${userProfile.decrypt_key}`
      );
      res.json({ decryptKey: userProfile.decrypt_key });
    } catch (error) {
      console.error(
        `[REQUEST-KEY] Error processing request-decryption-key for user ${userId} by bank ${requestingBankId}:`,
        error
      );
      if (error.code === "CALL_EXCEPTION" || error.code === "BAD_DATA") {
        console.error(
          "[REQUEST-KEY] Blockchain call (getParticipatingBanks) failed. Ensure contract address and RPC URL are correct for Customer Portal."
        );
      }
      res.status(500).json({
        error:
          "Failed to process decryption key request due to an internal error.",
        detail: error.message,
      });
    }
  }
);

/**
 * ✅ NEW ENDPOINT
 * POST /internal/sync-kyc-bundle
 * Called by a bank AFTER a successful on-chain `addKycVersion` call.
 * It receives the raw KTP/KYC data, creates a new encrypted bundle and a new
 * one-time decryption key, and stores them in the customer_portal.user_profiles table.
 */
router.post("/sync-kyc-bundle", authenticateBankRequest, async (req, res) => {
  const { userId, ktpData, kycData } = req.body;
  const callingBankId = req.requestingBankId; // from authenticateBankRequest middleware

  if (!userId || !ktpData || !kycData) {
    return res
      .status(400)
      .json({ error: "Missing userId, ktpData, or kycData" });
  }

  try {
    console.log(
      `[CP - /internal/sync-kyc-bundle] Request received for user ${userId} from bank ${callingBankId}.`
    );

    // 1. Generate new key and encrypted bundle
    const newGeneratedKeyHex = crypto.randomBytes(32).toString("hex");
    const bundleToEncryptString = JSON.stringify({ ktpData, kycData });

    // We need the aesEncrypt function. Let's define it here if not in a util.
    function internalAesEncrypt(text, keyHex) {
      const key = Buffer.from(keyHex, "hex");
      if (key.length !== 32) throw new Error("Invalid key length for AES-256.");
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
      let encrypted = cipher.update(text, "utf8", "hex");
      encrypted += cipher.final("hex");
      return iv.toString("hex") + ":" + encrypted;
    }

    const newEncryptedBundleHex = internalAesEncrypt(
      bundleToEncryptString,
      newGeneratedKeyHex
    );

    console.log(
      `[CP - /internal/sync-kyc-bundle] Generated new key and bundle for user ${userId}.`
    );

    // 2. Fetch current first_bank_code
    const [userProfileData] = await queryAsync(
      `SELECT first_bank_code FROM user_profiles WHERE user_id = ?`,
      [userId]
    );

    if (!userProfileData) {
      return res.status(404).json({
        error:
          "Cannot sync bundle, user profile does not exist in Customer Portal.",
      });
    }

    // 3. Determine and update the user_profiles record
    let finalFirstBankCode = userProfileData.first_bank_code || callingBankId;

    await queryAsync(
      `UPDATE user_profiles
         SET first_bank_code = ?,
             encrypted_bundle = ?,
             decrypt_key = ?,
             is_copied = 0,
             updated_at = NOW()
       WHERE user_id = ?`,
      [finalFirstBankCode, newEncryptedBundleHex, newGeneratedKeyHex, userId]
    );

    console.log(
      `[CP - /internal/sync-kyc-bundle] Successfully updated profile for user ${userId}.`
    );

    return res.json({
      success: true,
      message: "Customer Portal profile synced successfully.",
      newKey: newGeneratedKeyHex,
      newEncryptedBundle: newEncryptedBundleHex,
    });
  } catch (err) {
    console.error(
      `[CP - /internal/sync-kyc-bundle] Error for user ${userId}:`,
      err
    );
    return res
      .status(500)
      .json({ error: "Failed to sync KYC bundle.", detail: err.message });
  }
});

module.exports = router;
