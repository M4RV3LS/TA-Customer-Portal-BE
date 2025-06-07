// path file : customer-portal/backend/routes/userRoutes.js
const express = require("express");
const router = express.Router();
const fetch = require("node-fetch");
const session = require("express-session");
const { getBankApiBaseUrl } = require("../utils/bankHelper");

router.get("/profile-id", async (req, res) => {
  const uid = req.session.userId;
  if (!uid) return res.status(401).json({ error: "Not logged in" });

  try {
    // Determine the user's home bank
    const [userProfile] = await new Promise((resolve, reject) =>
      connection.query(
        "SELECT first_bank_code FROM user_profiles WHERE user_id = ?",
        [uid],
        (e, results) => (e ? reject(e) : resolve(results))
      )
    );

    const homeBankCode = userProfile?.first_bank_code;
    if (!homeBankCode) {
      // If no home bank, maybe they don't have a profile_id yet with any bank,
      // or we default to trying Bank A as a convention for this specific QR feature.
      console.warn(
        `[GET /profile-id] User ${uid} has no first_bank_code. Defaulting to BANK_A for profile-id lookup for QR.`
      );
      // This might be okay if the QR code URL structure is generic enough or if Bank A acts as a fallback.
      // Or return an error: return res.status(404).json({ error: "Home bank not established for user." });
    }

    const bankToQuery = homeBankCode || "BANK_A"; // Default to BANK_A if no home bank explicitly set
    const homeBankApiUrl = getBankApiBaseUrl(bankToQuery);

    if (!homeBankApiUrl) {
      return res
        .status(500)
        .json({ error: `Configuration error for bank: ${bankToQuery}` });
    }

    console.log(
      `[GET /profile-id] Fetching profile-ids for user ${uid} from ${bankToQuery} (${homeBankApiUrl})`
    );
    const bankRes = await fetch(
      `${homeBankApiUrl}/profile-ids?client_id=${uid}`
    );

    if (!bankRes.ok) {
      const errorText = await bankRes.text();
      console.error(
        `[GET /profile-id] Error fetching from ${bankToQuery}: ${bankRes.status} - ${errorText}`
      );
      return res.status(bankRes.status).json({
        error: `Failed to fetch profile ID from ${bankToQuery}`,
        detail: errorText,
      });
    }

    const rows = await bankRes.json();
    if (!Array.isArray(rows) || !rows.length) {
      // Ensure rows is an array
      return res.status(404).json({
        error: `No profile ID found for client ${uid} at ${bankToQuery}`,
      });
    }

    const last = rows[rows.length - 1];
    res.json({ profile_id: last.profile_id, bank_code: bankToQuery }); // Also return bank_code for clarity/use in frontend
  } catch (error) {
    console.error(`[GET /profile-id] Error for user ${uid}:`, error);
    res.status(500).json({ error: "Server error while fetching profile ID." });
  }
});

// *******************************************************************
// NEW ENDPOINT FOR GENERATING KYC REUSE QR CODE
// *******************************************************************
// router.post("/generate-kyc-qr", async (req, res) => {
//   const uid = req.session.userId;
//   if (!uid) {
//     return res.status(401).json({ error: "Not authenticated" });
//   }

//   try {
//     // 1. Fetch user credentials and profile in parallel
//     const [userCredentials] = await queryAsync(
//       "SELECT name, email, phone FROM users_credential WHERE id = ?",
//       [uid]
//     );

//     const [userProfile] = await queryAsync(
//       "SELECT first_bank_code FROM user_profiles WHERE user_id = ?",
//       [uid]
//     );

//     if (!userCredentials) {
//       return res.status(404).json({ error: "User credentials not found." });
//     }
//     if (!userProfile || !userProfile.first_bank_code) {
//       return res.status(400).json({
//         error: "Cannot generate reuse QR. No Home Bank is registered. Please complete a new KYC process first.",
//       });
//     }

//     // 2. Construct the payload
//     const payload = {
//       client_id: uid,
//       customer_name: userCredentials.name,
//       customer_email: userCredentials.email,
//       customer_phone: userCredentials.phone,
//       status_request: "reuse_kyc",
//       home_bank_code: userProfile.first_bank_code,
//     };

//     // 3. Generate QR code as a Data URL
//     const qrDataUrl = await QRCode.toDataURL(JSON.stringify(payload));

//     // 4. Send the QR code back to the frontend
//     res.json({ qrDataUrl });

//   } catch (error) {
//     console.error(`[POST /generate-kyc-qr] Error for user ${uid}:`, error);
//     res.status(500).json({ error: "Server error while generating QR code." });
//   }
// });

module.exports = router;
