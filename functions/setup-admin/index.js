const functions = require('@google-cloud/functions-framework');
const admin = require('firebase-admin');
const crypto = require('crypto');

const SA_KEY = process.env.FIREBASE_SA_KEY;
if (SA_KEY) {
  const credential = admin.credential.cert(JSON.parse(Buffer.from(SA_KEY, 'base64').toString()));
  admin.initializeApp({ credential });
} else {
  admin.initializeApp();
}

const SETUP_SECRET = process.env.SETUP_SECRET;

functions.http('setupAdmin', async (req, res) => {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method Not Allowed' });
    return;
  }

  const { id, pw, secret } = req.body || {};

  if (!SETUP_SECRET || secret !== SETUP_SECRET) {
    res.status(403).json({ error: 'Invalid secret' });
    return;
  }
  if (!id || !pw) {
    res.status(400).json({ error: 'id and pw are required' });
    return;
  }

  const pwHash = crypto.createHash('sha256').update(pw).digest('hex');
  await admin.firestore().doc('admin/credentials').set({ id, pwHash });

  res.json({ success: true, message: '관리자 계정이 저장되었습니다.' });
});
