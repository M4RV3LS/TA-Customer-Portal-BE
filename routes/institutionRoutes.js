// backend/routes/institutionRoutes.js
const express = require("express");
const router = express.Router();
const connection = require("../dbConnection");
const fetch = require("node-fetch");
const multer = require("multer");
const upload = multer({ dest: "uploads/" });
const fs = require("fs"); // For the /submit route
const { getBankApiBaseUrl } = require("../utils/bankHelper");

// 1) List all participating banks
//    GET /institutions
router.get("/", (req, res) => {
  const sql = `SELECT id, bank_id, name FROM regulator_portal.nodes ORDER BY name`;
  connection.query(sql, (err, rows) => {
    if (err) {
      console.error("MySQL error on listing institutions:", err);
      return res.status(500).json({ error: "Failed to fetch institutions" });
    }
    res.json(rows);
  });
});

// backend/routes/institutionRoutes.js
// Endpoint for user to initiate a NEW or UPDATE KYC with a bank (existing, but ensure it handles files)
router.post(
  "/:bankId/submit", // This is for new/update with files
  upload.fields([
    // Ensure multer is used here
    { name: "ktp", maxCount: 1 },
    { name: "kyc", maxCount: 1 },
  ]),
  async (req, res) => {
    const uid = req.session.userId; // user_id from customer_portal session
    if (!uid) return res.status(401).json({ error: "Not authenticated" });

    const { bankId } = req.params;
    // For new/update, client_id sent to the bank IS the user's ID in the customer portal.
    // The `profileId` from req.body in your original code for this endpoint seemed to be this uid.
    // Let's ensure consistency: client_id for bank systems is the uid from customer_portal.
    const {
      customer_name,
      customer_email,
      customer_phone,
      status_request = "new",
    } = req.body;

    const ktpFile = req.files?.ktp?.[0];
    const kycFile = req.files?.kyc?.[0];

    if (
      !customer_name ||
      !customer_email ||
      !customer_phone ||
      !ktpFile ||
      !kycFile
    ) {
      return res
        .status(400)
        .json({ error: "Missing fields for new/update submission." });
    }

    const encode = (file) => {
      const fs = require("fs"); // require fs here if not at top level
      const b = fs.readFileSync(file.path);
      fs.unlinkSync(file.path);
      return `data:${file.mimetype};base64,${b.toString("base64")}`;
    };
    const customer_ktp_datauri = encode(ktpFile);
    const customer_kyc_datauri = encode(kycFile);

    const payload = {
      client_id: uid, // User's ID in customer portal acts as client_id for banks
      customer_name,
      customer_email,
      customer_phone,
      customer_ktp: customer_ktp_datauri,
      customer_kyc: customer_kyc_datauri,
      status_request, // "new" or "update"
    };

    const port = bankId === "BANK_A" ? 4000 : bankId === "BANK_B" ? 5000 : null; // Example for Bank B
    if (!port) {
      return res.status(400).json({ error: "Invalid bankId provided." });
    }

    try {
      const bankRes = await fetch(`http://localhost:${port}/kyc-requests`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const json = await bankRes.json();
      res.status(bankRes.ok ? 200 : bankRes.status).json(json);
    } catch (e) {
      console.error(`Error forwarding new/update KYC to ${bankId}:`, e);
      res.status(502).json({ error: `Failed to submit KYC to ${bankId}` });
    }
  }
);

// NEW Endpoint for user to initiate REUSE KYC with a selected (second) bank
/**
 * POST /:bankId/submit-reuse
 * Endpoint for user to initiate REUSE KYC with a selected (Second) bank.
 * It forwards the request to the Second Bank's backend.
 */
router.post("/:bankId/submit-reuse", express.json(), async (req, res) => {
  const uid = req.session.userId;
  if (!uid) return res.status(401).json({ error: "Not authenticated" });

  const { bankId: secondBankId } = req.params;
  const { profileId, customer_name, customer_email, customer_phone } = req.body;

  if (uid !== profileId) {
    console.warn(
      `[SUBMIT-REUSE] User ID mismatch: session uid ${uid} vs. body profileId ${profileId}`
    );
    return res.status(403).json({ error: "User ID mismatch. Action denied." });
  }

  if (!customer_name || !customer_email || !customer_phone) {
    return res.status(400).json({
      error: "Missing customer details (name, email, phone) for reuse request.",
    });
  }

  let homeBankCodeForUser; // This will store the first_bank_code
  try {
    const [userProfileResults] = await new Promise(
      (
        resolve,
        reject // Renamed to avoid confusion if userProfile itself was needed later
      ) =>
        connection.query(
          "SELECT first_bank_code FROM user_profiles WHERE user_id = ?",
          [uid],
          (err, results) => (err ? reject(err) : resolve(results))
        )
    );

    if (!userProfileResults || !userProfileResults.first_bank_code) {
      console.error(
        `[SUBMIT-REUSE] User ${uid} has no established first_bank_code in customer_portal.user_profiles.`
      );
      return res.status(400).json({
        error:
          "Cannot initiate reuse: Your Home Bank information is not established in the Customer Portal.",
      });
    }
    homeBankCodeForUser = userProfileResults.first_bank_code; // Assign to the correctly scoped variable
  } catch (dbError) {
    console.error(
      `[SUBMIT-REUSE] DB error fetching first_bank_code for user ${uid}:`,
      dbError
    );
    return res
      .status(500)
      .json({ error: "Failed to retrieve user profile information." });
  }

  // Now, homeBankCodeForUser will be defined here (or the request would have ended with an error)
  const payloadToSecondBank = {
    client_id: uid,
    customer_name,
    customer_email,
    customer_phone,
    status_request: "reuse_kyc",
    home_bank_code: homeBankCodeForUser, // ✅ Use the correctly scoped variable
  };

  const secondBankApiUrl = getBankApiBaseUrl(secondBankId);
  if (!secondBankApiUrl) {
    return res.status(400).json({
      error: `Invalid bankId '${secondBankId}' for reuse submission.`,
    });
  }

  console.log(
    `[SUBMIT-REUSE] Forwarding KYC reuse request for user ${uid} to Second Bank ${secondBankId} (${secondBankApiUrl}). Home Bank is ${homeBankCodeForUser}.`
  );
  try {
    const secondBankRes = await fetch(`${secondBankApiUrl}/kyc-requests`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payloadToSecondBank),
    });
    const jsonResponse = await secondBankRes.json();
    res
      .status(secondBankRes.ok ? 200 : secondBankRes.status)
      .json(jsonResponse);
  } catch (e) {
    console.error(
      `Error forwarding KYC reuse request to ${secondBankId} (${secondBankApiUrl}):`,
      e
    );
    res.status(502).json({
      error: `Failed to submit KYC reuse request to ${secondBankId}. Please try again later.`,
    });
  }
});

module.exports = router;
