// customer-portal/backend/routes/accountRoutes.js
const express = require("express");
const router = express.Router();
const connection = require("../dbConnection");
const fetch = require("node-fetch");
const crypto = require("crypto");
const { getBankApiBaseUrl } = require("../utils/bankHelper");
const util = require("util");
const QRCode = require("qrcode");

// Promisify connection.query
const queryAsync = util.promisify(connection.query).bind(connection);

const AES_ALGORITHM = "aes-256-cbc";

function aesEncrypt(text, keyHex) {
  const key = Buffer.from(keyHex, "hex");
  if (key.length !== 32) throw new Error("Invalid key length for AES-256.");
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(AES_ALGORITHM, key, iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return iv.toString("hex") + ":" + encrypted;
}

function aesDecrypt(encryptedTextWithIv, keyHex) {
  const key = Buffer.from(keyHex, "hex");
  if (key.length !== 32) throw new Error("Invalid key length for AES-256.");
  const textParts = encryptedTextWithIv.split(":");
  if (textParts.length !== 2) throw new Error("Invalid encrypted text format.");
  const iv = Buffer.from(textParts.shift(), "hex");
  const encryptedText = textParts.join(":");
  if (iv.length !== 16) throw new Error("Invalid IV length.");
  const decipher = crypto.createDecipheriv(AES_ALGORITHM, key, iv);
  let decrypted = decipher.update(encryptedText, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

// -------------------------------
// GET /account
//   → returns basic account info (id, name, email, phone)
// -------------------------------
router.get("/", async (req, res) => {
  const uid = req.session.userId;
  if (!uid) return res.status(401).json({ error: "Not authenticated" });
  try {
    const rows = await queryAsync(
      `SELECT id, name, email, phone FROM users_credential WHERE id = ?`,
      [uid]
    );
    if (!rows || !rows.length) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json(rows[0]);
  } catch (err) {
    console.error("[CP GET /account] MySQL error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// -------------------------------
// PUT /account
//   → updates basic account info (name, email, phone)
// -------------------------------
router.put("/", express.json(), async (req, res) => {
  const uid = req.session.userId;
  if (!uid) return res.status(401).json({ error: "Not authenticated" });

  const { name, email, phone } = req.body;
  if (!name || !email || !phone) {
    return res.status(400).json({ error: "Missing name, email, or phone" });
  }
  try {
    await queryAsync(
      `UPDATE users_credential SET name = ?, email = ?, phone = ? WHERE id = ?`,
      [name, email, phone, uid]
    );
    res.json({ message: "Account updated successfully" });
  } catch (err) {
    console.error("[CP PUT /account] MySQL error:", err);
    return res.status(500).json({ error: "Update failed" });
  }
});

// -------------------------------
// GET /account/profile
//   → returns KYC/profile metadata, including decryptKey & is_copied
//   Behavior:
//     • If encryptedBundle & decryptKey & ?key provided → decrypt, return data, nullify decryptKey, leave is_copied unchanged
//     • If encryptedBundle & !decryptKey → regenerate key from home bank, reset is_copied = 0
//     • Otherwise → return current state (with is_copied flag)
// -------------------------------
router.get("/profile", async (req, res) => {
  const uid = req.session.userId;
  console.log(`[CP GET /account/profile] Called for user_id: ${uid}`);
  if (!uid) {
    console.log("[CP GET /account/profile] Not authenticated.");
    return res.status(401).json({ error: "Not authenticated" });
  }

  try {
    console.log(
      `[CP GET /account/profile] Fetching user_profile for user_id: ${uid}`
    );
    const userProfiles = await queryAsync(
      `SELECT
         user_id           AS userId,
         first_bank_code   AS firstBankCode,
         decrypt_key       AS decryptKey,
         encrypted_bundle  AS encryptedBundle,
         is_copied         AS is_copied
       FROM user_profiles
       WHERE user_id = ?`,
      [uid]
    );

    const userProfile =
      userProfiles && userProfiles.length > 0 ? userProfiles[0] : null;

    console.log(
      "[CP GET /account/profile] Fetched userProfile from DB:",
      userProfile
        ? {
            userId: userProfile.userId,
            firstBankCode: userProfile.firstBankCode,
            decryptKey: userProfile.decryptKey ? "******" : null,
            encryptedBundle: userProfile.encryptedBundle ? "******" : null,
            is_copied: userProfile.is_copied === 1,
          }
        : null
    );

    if (!userProfile) {
      console.warn(
        `[CP GET /account/profile] No record in user_profiles for user_id: ${uid}.`
      );
      return res.status(404).json({
        error: "USER_PROFILE_NOT_FOUND",
        message: "User profile data does not exist.",
      });
    }

    // Convert is_copied TINYINT(1) → boolean
    const alreadyCopied = userProfile.is_copied === 1;

    // Scenario 1: User provided ?key to decrypt and view
    if (
      userProfile.encryptedBundle &&
      userProfile.decryptKey &&
      req.query.key
    ) {
      console.log(
        `[CP GET /account/profile] User ${uid} attempting to view documents with provided key.`
      );
      const providedKey = String(req.query.key);
      if (providedKey !== userProfile.decryptKey) {
        console.warn(
          `[CP GET /account/profile] User ${uid}: Invalid decrypt key provided.`
        );
        return res.status(403).json({ error: "INVALID_DECRYPT_KEY" });
      }
      try {
        const decryptedBundleJsonString = aesDecrypt(
          userProfile.encryptedBundle,
          userProfile.decryptKey
        );
        const bundleContent = JSON.parse(decryptedBundleJsonString);
        console.log(
          `[CP GET /account/profile] User ${uid}: Successfully decrypted bundle. Nullifying key.`
        );
        await queryAsync(
          `UPDATE user_profiles SET decrypt_key = NULL WHERE user_id = ?`,
          [uid]
        );
        return res.json({
          ktpData: bundleContent.ktpData,
          kycData: bundleContent.kycData,
          is_copied: alreadyCopied,
        });
      } catch (decryptErr) {
        console.error(
          `[CP GET /account/profile] User ${uid}: Decryption failed:`,
          decryptErr
        );
        return res.status(500).json({ error: "DECRYPTION_ERROR" });
      }
    }

    // Scenario 2: Key needs regeneration (bundle exists, but key is NULL)
    if (userProfile.encryptedBundle && !userProfile.decryptKey) {
      console.log(
        `[CP GET /account/profile] User ${uid}: Bundle exists, decryptKey is NULL. Regenerating key by fetching from Home Bank: ${userProfile.firstBankCode}.`
      );
      const homeBankForRegen = userProfile.firstBankCode;
      if (!homeBankForRegen) {
        console.error(
          `[CP GET /account/profile] User ${uid}: Cannot regenerate key. Home Bank (firstBankCode) is not set, but a bundle exists. Inconsistent state.`
        );
        return res
          .status(500)
          .json({ error: "INCONSISTENT_PROFILE_NO_HOMEBANK" });
      }
      const homeBankApiUrl = getBankApiBaseUrl(homeBankForRegen);
      if (!homeBankApiUrl) {
        console.error(
          `[CP GET /account/profile] User ${uid}: Home Bank API base URL not found for code: ${homeBankForRegen}.`
        );
        return res.status(500).json({ error: "HOMEBANK_URL_NOT_CONFIGURED" });
      }

      const bankRes = await fetch(
        `${homeBankApiUrl}/kyc-requests?client_id=${uid}`
      );
      if (!bankRes.ok) {
        console.error(
          `[CP GET /account/profile] User ${uid}: Home Bank responded with status ${bankRes.status}.`
        );
        return res
          .status(502)
          .json({ error: "HOMEBANK_FETCH_ERROR", status: bankRes.status });
      }
      const kycRequests = await bankRes.json();
      if (
        !Array.isArray(kycRequests) ||
        !kycRequests.length ||
        !kycRequests[0].customer_ktp ||
        !kycRequests[0].customer_kyc
      ) {
        console.warn(
          `[CP GET /account/profile] User ${uid}: Home Bank ${homeBankForRegen} returned no/incomplete data for key regeneration.`
        );
        return res.json({
          profileId: userProfile.userId,
          userId: userProfile.userId,
          firstBankCode: userProfile.firstBankCode,
          decryptKey: null,
          hasEncryptedBundle: true,
          is_copied: alreadyCopied,
          message:
            "Key requires regeneration, but Home Bank data is currently unavailable.",
        });
      }
      const { customer_ktp: rawKtpData, customer_kyc: rawKycData } =
        kycRequests[0];
      const newKeyHex = crypto.randomBytes(32).toString("hex");
      const bundleString = JSON.stringify({
        ktpData: rawKtpData,
        kycData: rawKycData,
      });
      const newEncryptedBundle = aesEncrypt(bundleString, newKeyHex);
      await queryAsync(
        `UPDATE user_profiles
           SET encrypted_bundle = ?,
               decrypt_key      = ?,
               is_copied        = 0,
               updated_at       = NOW()
         WHERE user_id = ?`,
        [newEncryptedBundle, newKeyHex, uid]
      );
      console.log(
        `[CP GET /account/profile] User ${uid}: Key regenerated. New key prefix: ${newKeyHex.substring(
          0,
          6
        )}`
      );
      return res.json({
        profileId: userProfile.userId,
        userId: userProfile.userId,
        firstBankCode: userProfile.firstBankCode,
        decryptKey: newKeyHex,
        hasEncryptedBundle: true,
        is_copied: false,
      });
    }

    // Default: Return current profile state (for new users with NULLs, or existing users wanting metadata)
    console.log(
      `[CP GET /account/profile] User ${uid}: Returning current profile state. First Bank: ${
        userProfile.firstBankCode
      }, Has Key: ${!!userProfile.decryptKey}, is_copied: ${alreadyCopied}`
    );
    return res.json({
      profileId: userProfile.userId,
      userId: userProfile.userId,
      firstBankCode: userProfile.firstBankCode,
      decryptKey: userProfile.decryptKey,
      hasEncryptedBundle: !!userProfile.encryptedBundle,
      is_copied: alreadyCopied,
    });
  } catch (err) {
    console.error(
      `[CP GET /account/profile] Outer catch block for user ${req.session.userId}: ${err.message}`,
      err.stack
    );
    if (!res.headersSent) {
      return res
        .status(500)
        .json({ error: "SERVER_ERROR_PROFILE_MAIN", message: err.message });
    }
  }
});

// -------------------------------
// POST /account/profile/copied
//   → Sets is_copied = TRUE for the current user
// -------------------------------
router.post("/profile/copied", async (req, res) => {
  const uid = req.session.userId;
  if (!uid) return res.status(401).json({ error: "Not authenticated" });
  try {
    await queryAsync(
      `UPDATE user_profiles
         SET is_copied = 1
       WHERE user_id = ?`,
      [uid]
    );
    return res.json({ success: true });
  } catch (err) {
    console.error(
      `[CP POST /account/profile/copied] Error updating is_copied for user ${uid}:`,
      err
    );
    return res.status(500).json({ error: "Server error updating is_copied" });
  }
});

// -------------------------------
// POST /account/rotate-key
//   → Rotates (generates) a new decrypt key & bundle, resets is_copied = 0
//   Body: { userId: number, ktpData: string, kycData: string, callingBankId: string }
// -------------------------------
router.post(
  "/rotate-key",
  express.json({ limit: "50mb" }),
  async (req, res) => {
    const {
      userId,
      ktpData: providedKtpDataUri,
      kycData: providedKycDataUri,
      callingBankId,
    } = req.body;

    if (!userId || typeof userId !== "number")
      return res.status(400).json({ error: "Missing or invalid userId" });
    if (!callingBankId)
      return res.status(400).json({
        error: "MISSING_CALLING_BANK_ID",
        message: "Bank identifier (callingBankId) is required.",
      });
    if (!providedKtpDataUri || !providedKycDataUri)
      return res.status(400).json({
        error: "MISSING_KTP_KYC_DATA",
        message: "KTP and KYC data URIs must be provided.",
      });

    try {
      console.log(
        `[CP - /account/rotate-key] User ${userId}: Rotation initiated by ${callingBankId}.`
      );
      console.log(
        `  Using KTP data (len ${
          String(providedKtpDataUri).length
        }, prefix 70): ${String(providedKtpDataUri).substring(0, 70)}...`
      );
      console.log(
        `  Using KYC data (len ${
          String(providedKycDataUri).length
        }, prefix 70): ${String(providedKycDataUri).substring(0, 70)}...`
      );

      const [userProfileData] = await queryAsync(
        `SELECT first_bank_code FROM user_profiles WHERE user_id = ?`,
        [userId]
      );

      if (!userProfileData) {
        console.error(
          `[CP - /account/rotate-key] User ${userId}: No existing user_profiles record. This is unexpected.`
        );
        return res
          .status(404)
          .json({ error: "USER_PROFILE_NOT_FOUND_FOR_ROTATE" });
      }

      const newGeneratedKeyHex = crypto.randomBytes(32).toString("hex");
      const bundleToEncryptString = JSON.stringify({
        ktpData: providedKtpDataUri,
        kycData: providedKycDataUri,
      });
      const newEncryptedBundleHex = aesEncrypt(
        bundleToEncryptString,
        newGeneratedKeyHex
      );

      console.log(
        `[CP - /account/rotate-key] User ${userId}: Encrypted new bundle (len ${
          newEncryptedBundleHex.length
        }, prefix 100): ${newEncryptedBundleHex.substring(
          0,
          100
        )}... with newKey (prefix 6): ${newGeneratedKeyHex.substring(0, 6)}`
      );

      let finalFirstBankCode = userProfileData.first_bank_code;
      if (!finalFirstBankCode) {
        finalFirstBankCode = callingBankId;
        console.log(
          `[CP - /account/rotate-key] User ${userId}: Setting first_bank_code to ${finalFirstBankCode}.`
        );
      } else if (finalFirstBankCode !== callingBankId) {
        console.warn(
          `[CP - /account/rotate-key] User ${userId}: Call from ${callingBankId}, but existing first_bank_code is ${finalFirstBankCode}. Retaining existing: ${finalFirstBankCode}.`
        );
      }

      await queryAsync(
        `UPDATE user_profiles
           SET first_bank_code  = ?,
               encrypted_bundle = ?,
               decrypt_key      = ?,
               is_copied        = 0,
               updated_at       = NOW()
         WHERE user_id = ?`,
        [finalFirstBankCode, newEncryptedBundleHex, newGeneratedKeyHex, userId]
      );

      console.log(
        `[CP - /account/rotate-key] Successfully updated CP profile for user ${userId}. Returning key/bundle. First_bank_code: ${finalFirstBankCode}.`
      );
      return res.json({
        success: true,
        newKey: newGeneratedKeyHex,
        newEncryptedBundle: newEncryptedBundleHex,
        message: "Key rotated and profile updated successfully",
      });
    } catch (err) {
      console.error(
        `[CP - /account/rotate-key] Unexpected error for user ${req.body.userId}:`,
        err.message,
        err.stack
      );
      if (!res.headersSent) {
        return res
          .status(500)
          .json({ error: "KEY_ROTATION_FAILED_CP", message: err.message });
      }
    }
  }
);

router.get("/qr", async (req, res) => {
  const uid = req.session.userId;
  if (!uid) return res.status(401).json({ error: "Not authenticated" });

  // 1) fetch the user + profile data
  const [user] = await queryAsync(
    `SELECT name,email,phone FROM users_credential WHERE id=?`,
    [uid]
  );
  const [profile] = await queryAsync(
    `SELECT first_bank_code AS homeBankCode FROM user_profiles WHERE user_id=?`,
    [uid]
  );
  if (!user || !profile) {
    return res.status(404).json({ error: "Profile not found" });
  }

  // 2) build the payload
  const payload = {
    client_id: uid,
    customer_name: user.name,
    customer_email: user.email,
    customer_phone: user.phone,
    status_request: "reuse_kyc",
    home_bank_code: profile.homeBankCode,
  };

  try {
    // 3) render QR as Data URL
    const dataUrl = await QRCode.toDataURL(JSON.stringify(payload), {
      width: 400,
    });
    res.json({ qrDataUrl: dataUrl });
  } catch (e) {
    console.error("[GET /account/qr] QR generation failed:", e);
    res.status(500).json({ error: "QR generation error" });
  }
});

module.exports = router;
