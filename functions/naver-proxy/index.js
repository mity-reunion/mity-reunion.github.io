const { onRequest } = require('@google-cloud/functions-framework/build/src/functions');
const functions = require('@google-cloud/functions-framework');

const ALLOWED_ORIGIN = 'https://mity-reunion.github.io';

functions.http('naverProxy', async (req, res) => {
  res.set('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.status(204).send('');
    return;
  }

  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method Not Allowed' });
    return;
  }

  const token = req.body?.token;
  if (!token) {
    res.status(400).json({ error: 'token is required' });
    return;
  }

  try {
    const response = await fetch('https://openapi.naver.com/v1/nid/me', {
      headers: { Authorization: 'Bearer ' + token },
    });
    const data = await response.json();
    res.status(response.status).json(data);
  } catch (e) {
    console.error('Naver API error', e);
    res.status(500).json({ error: 'Failed to fetch Naver profile' });
  }
});
