require('dotenv').config(); // Load environment variables from .env file

const express = require('express');
const bodyParser = require('body-parser');
const authRoutes = require('./authRoutes'); // Import your authentication routes

const app = express(); // Initialize the app here

// Environment variables
const PORT = process.env.PORT || 3000;
const OAUTH_SERVER_SECRET = process.env.OAUTH_SERVER_SECRET;
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const ISSUER_URL = process.env.ISSUER_URL;
const REDIRECT_URI = process.env.REDIRECT_URI;

// Global Middleware for Logging
app.use((req, res, next) => {
  console.log(`\n[${new Date().toISOString()}] Incoming Request`);
  console.log(`Method: ${req.method}`);
  console.log(`URL: ${req.url}`);
  console.log('Headers:', req.headers);
  if (req.body && Object.keys(req.body).length) {
    console.log('Body:', req.body);
  } else {
    console.log('Body: <Empty>');
  }
  next();
});

// Middleware
app.use(bodyParser.json());
app.use('/auth', authRoutes); // Routes for authentication

// Root Route
app.get('/', (req, res) => {
  res.send('<h1>Welcome to the OAuth Server</h1><p>Use the appropriate endpoints for authentication.</p>');
});

// Start the server
app.listen(PORT, () => {
  console.log(`\nServer running on http://localhost:${PORT}`);
  console.log(`OIDC Provider (Issuer URL): ${ISSUER_URL}`);
  console.log(`Redirect URI: ${REDIRECT_URI}`);
});
