const jwt = require('jsonwebtoken');

// Generate an authorization code (JWT)
const generateAuthCode = (payload) => {
  return jwt.sign(payload, process.env.OAUTH_SERVER_SECRET, { expiresIn: '5m' });
};

// Verify an authorization code (JWT)
const verifyAuthCode = (token) => {
  return jwt.verify(token, process.env.OAUTH_SERVER_SECRET);
};

// Generate an ID token (JWT)
const generateIdToken = (payload) => {
  const { exp, ...cleanPayload } = payload; // Avoid conflict with 'expiresIn'

  return jwt.sign(
    {
      ...cleanPayload,
      iss: process.env.ISSUER_URL,
      aud: process.env.CLIENT_ID,
    },
    process.env.OAUTH_SERVER_SECRET,
    { expiresIn: process.env.TOKEN_EXPIRY || '1h' }
  );
};

// Generate an Access Token (JWT)
const generateAccessToken = (payload) => {
  const { exp, ...cleanPayload } = payload; // Avoid conflict with 'expiresIn'

  return jwt.sign(cleanPayload, process.env.OAUTH_SERVER_SECRET, {
    expiresIn: '1h', // Default expiry: 1 hour
  });
};

// Middleware to verify an ID token
const verifyIdToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(403).json({ error: 'No token provided' });
  }

  try {
    const payload = jwt.verify(token, process.env.OAUTH_SERVER_SECRET);

    // OIDC-specific validations
    if (payload.iss !== process.env.ISSUER_URL) {
      console.error('Invalid issuer:', payload.iss);
      throw new Error('Invalid issuer');
    }
    if (payload.aud !== process.env.CLIENT_ID) {
      console.error('Invalid audience:', payload.aud);
      throw new Error('Invalid audience');
    }

    req.user = payload; // Attach decoded user info to request
    next();
  } catch (err) {
    console.error('Error verifying ID token:', err.message);
    res.status(401).json({ error: 'Unauthorized', message: err.message });
  }
};

module.exports = {
  generateAuthCode,
  verifyAuthCode,
  generateIdToken,
  generateAccessToken,
  verifyIdToken,
};
