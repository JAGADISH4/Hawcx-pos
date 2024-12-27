const express = require('express');
const jwtUtils = require('./jwtUtils');
const bcrypt = require('bcrypt');
const { users } = require('./users');

const router = express.Router();

// Authorization Code Store
const authorizationCodes = new Map();
const CODE_EXPIRATION_TIME = 5 * 60 * 1000; // 5 minutes

function storeAuthorizationCode(code, data) {
  console.log('Storing authorization code:', code, 'with data:', data);
  authorizationCodes.set(code, { ...data, expiresAt: Date.now() + CODE_EXPIRATION_TIME });
}

function getAuthorizationCode(code) {
  console.log('Retrieving authorization code:', code);
  const data = authorizationCodes.get(code);
  if (!data || Date.now() > data.expiresAt) {
    console.error('Authorization code expired or not found:', code);
    authorizationCodes.delete(code);
    return null;
  }
  return data;
}

// Authorization Endpoint
router.post('/authorize', (req, res) => {
  console.log('POST /authorize reached');
  console.log('Incoming POST /authorize request');
  console.log('Request Body:', req.body);

  const { username, password, client_id, redirect_uri, response_type, scope } = req.body;

  // Validate client_id and redirect_uri
  if (client_id !== process.env.CLIENT_ID || redirect_uri !== process.env.REDIRECT_URI) {
    console.error('Invalid client_id or redirect_uri');
    return res.status(400).json({ error: 'Invalid client_id or redirect_uri' });
  }

  // Validate response_type
  if (response_type !== 'code') {
    console.error('Invalid response_type:', response_type);
    return res.status(400).json({ error: 'Invalid response_type. Expected "code".' });
  }

  // Validate scope
  if (!scope || !scope.includes('openid')) {
    console.error('Scope must include "openid". Received:', scope);
    return res.status(400).json({ error: 'Scope must include "openid".' });
  }

  const supportedScopes = ['openid', 'email', 'profile'];
  const requestedScopes = scope.split(' ');

  const invalidScopes = requestedScopes.filter((s) => !supportedScopes.includes(s));
  if (invalidScopes.length > 0) {
    console.error('Unsupported scope(s):', invalidScopes);
    return res.status(400).json({ error: `Unsupported scope(s): ${invalidScopes.join(', ')}` });
  }

  // Authenticate user
  const user = users.find((u) => u.username === username);
  if (!user) {
    console.error('User not found:', username);
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  if (!bcrypt.compareSync(password, user.password)) {
    console.error('Invalid password for user:', username);
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  console.log('User authenticated successfully:', username);

  // Generate authorization code
  const authorizationCode = jwtUtils.generateAuthCode({
    username: user.username,
    scope: requestedScopes,
  });

  console.log('Generated authorization code:', authorizationCode);

  // Redirect to the redirect_uri with the authorization_code
  const redirectUrl = `${redirect_uri}?code=${authorizationCode}`;
  console.log('Redirecting to:', redirectUrl);

  return res.redirect(redirectUrl); // Ensure only one response is sent
});

// Token Endpoint
router.post('/token', (req, res) => {
  console.log('Incoming POST /token request');
  console.log('Request Body:', req.body);

  const { code, client_id, client_secret } = req.body; // Use 'code' instead of 'authorization_code'

  // Validate client_id and client_secret
  if (client_id !== process.env.CLIENT_ID || client_secret !== process.env.CLIENT_SECRET) {
    console.error('Invalid client_id or client_secret');
    return res.status(401).json({ error: 'Invalid client credentials' });
  }

  try {
    // Verify the authorization code
    const payload = jwtUtils.verifyAuthCode(code); // Match the field name 'code'

    console.log('Authorization code verified:', code);

    // Generate tokens
    const idToken = jwtUtils.generateIdToken(payload);
    const accessToken = jwtUtils.generateAccessToken(payload); // Assuming you have a function for access tokens

    console.log('Generated tokens: id_token and access_token');

    // Send tokens as response
    res.json({
      id_token: idToken,
      access_token: accessToken,
      token_type: 'Bearer',
    });
  } catch (err) {
    console.error('Error verifying authorization code:', err.message);
    res.status(400).json({ error: 'Invalid authorization code' });
  }
});

// Step 1: OIDC Discovery Endpoint
router.get('/.well-known/openid-configuration', (req, res) => {
  const baseUrl = process.env.ISSUER_URL;
  res.json({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/auth/authorize`,
    token_endpoint: `${baseUrl}/auth/token`,
    userinfo_endpoint: `${baseUrl}/auth/userinfo`,
    jwks_uri: `${baseUrl}/auth/keys`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256', 'HS256'],
    scopes_supported: ['openid', 'email', 'profile'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
  });
});

// Step 2: UserInfo Endpoint
router.get('/userinfo', jwtUtils.verifyIdToken, (req, res) => {
  console.log('Fetching user info for:', req.user);

  const { username, scope } = req.user;

  // Simulate fetching user details (could be from a DB)
  const user = users.find((u) => u.username === username);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  // Filter data based on scopes
  const userInfo = {};
  if (scope.includes('email')) userInfo.email = user.email;
  if (scope.includes('profile')) userInfo.profile = { name: user.name };

  res.json({
    sub: username, // OIDC 'sub' claim
    ...userInfo,
  });
});

module.exports = router;
