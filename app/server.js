
'use strict';

const express = require('express');
const session = require('express-session');
const { csrfSync } = require('csrf-sync');
require('dotenv').config();

const app = express();

const PORT = Number(process.env.PORT || 3000);
const BASE_URL = new URL(
  process.env.BASE_URL || `http://localhost:${PORT}`
);

const SESSION_SECRET = process.env.SESSION_SECRET;
const COOKIE_NAME = 'oauthlab.sid';

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  throw new Error('SESSION_SECRET must be at least 32 characters');
}

if (process.env.TRUST_PROXY === '1') {
  app.set('trust proxy', 1);
}

app.disable('x-powered-by');

app.use(express.json({ limit: '10kb' }));

// Session configuration
app.use(session({
  name: COOKIE_NAME,
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,

    // HTTPS in production; HTTP allowed for local development.
    secure: process.env.NODE_ENV === 'production',

    sameSite: 'lax',
    path: '/',
    maxAge: 15 * 60 * 1000

    // Domain is intentionally omitted:
    // the cookie remains host-only.
    // maxAge is used instead of manually setting expires.
  }
}));

// CSRF protection configuration
const {
  generateToken,
  csrfSynchronisedProtection
} = csrfSync();

let oidc;
let oidcConfig = null;

const REDIRECT_URI = new URL('/callback', BASE_URL).href;

// Home page
app.get('/', (req, res) => {
  res.send('OAuthLab6 - OpenID Connect Security Lab');
});

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    oidcConfigured: Boolean(oidcConfig)
  });
});

// Generate CSRF token
app.get('/csrf-token', (req, res) => {
  res.set('Cache-Control', 'no-store');

  res.json({
    token: generateToken(req)
  });
});

// Protect state-changing requests.
// GET, HEAD and OPTIONS are ignored by csrf-sync.
app.use(csrfSynchronisedProtection);

// Start authentication
app.get('/login', async (req, res, next) => {
  if (!oidcConfig) {
    return res.status(503).json({
      error: 'OIDC provider is not configured'
    });
  }

  try {
    const codeVerifier = oidc.randomPKCECodeVerifier();

    const codeChallenge =
      await oidc.calculatePKCECodeChallenge(codeVerifier);

    const state = oidc.randomState();
    const nonce = oidc.randomNonce();

    const authorizationUrl = oidc.buildAuthorizationUrl(
      oidcConfig,
      {
        redirect_uri: REDIRECT_URI,
        scope: 'openid profile email',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        state,
        nonce
      }
    );

    req.session.authTransaction = {
      codeVerifier,
      state,
      nonce
    };

    req.session.save((error) => {
      if (error) return next(error);

      res.redirect(authorizationUrl.href);
    });

  } catch (error) {
    next(error);
  }
});

// OpenID Connect callback
app.get('/callback', async (req, res, next) => {
  if (!oidcConfig) {
    return res.status(503).json({
      error: 'OIDC provider is not configured'
    });
  }

  const transaction = req.session.authTransaction;

  if (!transaction) {
    return res.status(400).json({
      error: 'Authentication transaction not found'
    });
  }

  try {
    const currentUrl = new URL(req.originalUrl, BASE_URL);

    const tokens = await oidc.authorizationCodeGrant(
      oidcConfig,
      currentUrl,
      {
        pkceCodeVerifier: transaction.codeVerifier,
        expectedState: transaction.state,
        expectedNonce: transaction.nonce,
        idTokenExpected: true
      }
    );

    const claims = tokens.claims();

    if (!claims || !claims.sub) {
      return res.status(401).json({
        error: 'Invalid identity token'
      });
    }

    // Prevent session fixation
    await new Promise((resolve, reject) => {
      req.session.regenerate((error) => {
        if (error) reject(error);
        else resolve();
      });
    });

    req.session.user = {
      id: claims.sub,
      name: claims.name || null,
      email: claims.email || null
    };

    res.redirect('/profile');

  } catch (error) {
    next(error);
  }
});

// Protected profile
app.get('/profile', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({
      error: 'Unauthorized'
    });
  }

  res.json({
    message: 'Authentication successful',
    user: req.session.user
  });
});

// Logout - requires a valid CSRF token
app.post('/logout', (req, res, next) => {
  req.session.destroy((error) => {
    if (error) return next(error);

    res.clearCookie(COOKIE_NAME, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/'
    });

    res.json({
      message: 'Logged out'
    });
  });
});

// Centralized error handler
app.use((error, req, res, next) => {
  if (res.headersSent) {
    return next(error);
  }

  // Handle invalid or missing CSRF tokens
  if (error.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({
      error: 'Invalid or missing CSRF token'
    });
  }

  console.error('Request processing failed');

  res.status(500).json({
    error: 'Internal server error'
  });
});

// Initialize application
async function start() {
  if (process.env.OIDC_ISSUER && process.env.OIDC_CLIENT_ID) {
    oidc = await import('openid-client');

    oidcConfig = await oidc.discovery(
      new URL(process.env.OIDC_ISSUER),
      process.env.OIDC_CLIENT_ID,
      undefined,
      oidc.None()
    );
  } else {
    console.warn('OIDC provider is not configured');
  }

  app.listen(PORT, () => {
    console.log(`OAuthLab6 running on port ${PORT}`);
  });
}

start().catch(() => {
  console.error('Application startup failed');
  process.exit(1);
});
