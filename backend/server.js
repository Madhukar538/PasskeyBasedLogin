require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { MongoClient, ObjectId } = require('mongodb');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const MONGO_URI = process.env.MONGO_URI;
const DATABASE_NAME = process.env.DATABASE_NAME;
const RP_ID = process.env.RP_ID;
const ORIGIN = process.env.ORIGIN;
let usersCollection;

MongoClient.connect(MONGO_URI, { useUnifiedTopology: true })
  .then(client => {
    const db = client.db(DATABASE_NAME);
    usersCollection = db.collection('users');
    app.listen(3000, () => console.log('Backend running on http://localhost:3000'));
  })
  .catch(err => console.error('MongoDB connection failed:', err));

// Registration challenge
app.post('/register/options', async (req, res) => {
  const { username } = req.body;
  let user = await usersCollection.findOne({ username });
  if (!user) {
    user = { username, id: new ObjectId().toString(), credentials: [] };
    await usersCollection.insertOne(user);
  }
  const options = generateRegistrationOptions({
    rpName: 'Angular Passkey Demo',
    rpID: RP_ID,
    userID: user.id,
    userName: user.username,
    attestationType: 'none',
  });
  await usersCollection.updateOne({ username }, { $set: { currentChallenge: options.challenge } });
  res.json(options);
});

// Registration verification
app.post('/register/verify', async (req, res) => {
  const { username, attestation } = req.body;
  const user = await usersCollection.findOne({ username });
  try {
    const verification = verifyRegistrationResponse({
      response: attestation,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
    });
    if (verification.verified) {
      await usersCollection.updateOne(
        { username },
        { $push: { credentials: verification.registrationInfo } }
      );
      res.json({ verified: true });
    } else {
      res.status(400).json({ verified: false });
    }
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Authentication challenge
app.post('/login/options', async (req, res) => {
  const { username } = req.body;
  const user = await usersCollection.findOne({ username });
  if (!user) return res.status(404).json({ error: 'User not found' });
  const options = generateAuthenticationOptions({
    rpID: RP_ID,
    userVerification: 'preferred',
    allowCredentials: user.credentials.map(cred => ({
      id: cred.credentialID,
      type: 'public-key',
      transports: ['internal'],
    })),
  });
  await usersCollection.updateOne({ username }, { $set: { currentChallenge: options.challenge } });
  res.json(options);
});

// Authentication verification
app.post('/login/verify', async (req, res) => {
  const { username, assertion } = req.body;
  const user = await usersCollection.findOne({ username });
  try {
    const verification = verifyAuthenticationResponse({
      response: assertion,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      authenticator: user.credentials[0],
    });
    if (verification.verified) {
      res.json({ verified: true });
    } else {
      res.status(400).json({ verified: false });
    }
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});
