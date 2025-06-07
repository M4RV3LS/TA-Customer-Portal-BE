// customer-portal/backend/utils/bankHelper.js
const BANK_PORTS = {
  BANK_A: 4000,
  BANK_B: 5000,
  // Add other banks here as needed: 'BANK_C': 6000,
};

function getBankPort(bankId) {
  return BANK_PORTS[bankId] || null;
}

function getBankApiBaseUrl(bankId) {
  const port = getBankPort(bankId);
  if (!port) return null;
  return `http://localhost:${port}`;
}

module.exports = { getBankPort, getBankApiBaseUrl };
