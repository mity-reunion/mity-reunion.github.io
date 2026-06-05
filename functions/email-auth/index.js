const functions = require('@google-cloud/functions-framework');
const admin = require('firebase-admin');

const SA_KEY = process.env.FIREBASE_SA_KEY;
if (SA_KEY) {
  const credential = admin.credential.cert(JSON.parse(Buffer.from(SA_KEY, 'base64').toString()));
  admin.initializeApp({ credential });
} else {
  admin.initializeApp();
}

const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'https://mity-reunion.github.io';
const SITE_URL = 'https://mity-reunion.github.io/booking.html';
const BREVO_API_KEY = process.env.BREVO_SMTP_KEY;
const SENDER_EMAIL = process.env.BREVO_USER || 'mityreunion@gmail.com';

function setCors(res) {
  res.set('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type');
}

function emailHtml(link) {
  return `<!DOCTYPE html>
<html lang="ko">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#000;font-family:'Apple SD Gothic Neo',sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;margin:40px auto;background:#0a0a0a;border:1px solid rgba(255,255,255,0.1);border-radius:8px;overflow:hidden;">
    <tr><td style="background:#000;padding:32px 40px;text-align:center;letter-spacing:0.2em;">
      <span style="color:#fff;font-weight:900;font-size:1.1rem;">M.I.T.Y</span>
    </td></tr>
    <tr><td style="padding:40px;color:#fff;">
      <p style="font-size:1.2rem;font-weight:700;margin:0 0 8px;">예매 인증</p>
      <p style="font-size:0.85rem;color:rgba(255,255,255,0.55);margin:0 0 32px;">M.I.T.Y REUNION · 07.11 SAT 2PM</p>
      <p style="font-size:0.9rem;color:rgba(255,255,255,0.75);line-height:1.8;margin:0 0 32px;">
        아래 버튼을 클릭하면 예매 페이지로 이동합니다.<br>
        링크는 1시간 동안 유효합니다.
      </p>
      <a href="${link}" style="display:inline-block;padding:14px 32px;background:#fff;color:#000;font-weight:900;font-size:0.95rem;letter-spacing:0.1em;text-decoration:none;border-radius:4px;box-shadow:3px 3px 0 #cc2200;">예매하러 가기</a>
      <p style="margin:32px 0 0;font-size:0.72rem;color:rgba(255,255,255,0.3);line-height:1.8;">
        본인이 요청하지 않은 경우 이 메일을 무시하세요.<br>
        수집된 개인정보는 공연 종료 후 즉시 폐기됩니다.
      </p>
    </td></tr>
  </table>
</body></html>`;
}

functions.http('emailAuth', async (req, res) => {
  setCors(res);
  if (req.method === 'OPTIONS') { res.status(204).send(''); return; }
  if (req.method !== 'POST') { res.status(405).json({ error: 'Method Not Allowed' }); return; }

  const { email } = req.body;
  if (!email) { res.status(400).json({ error: 'email is required' }); return; }

  try {
    const link = await admin.auth().generateSignInWithEmailLink(email, {
      url: `${SITE_URL}?email=${encodeURIComponent(email)}`,
      handleCodeInApp: true,
    });

    const emailRes = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'api-key': BREVO_API_KEY,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        sender: { name: 'M.I.T.Y REUNION', email: SENDER_EMAIL },
        to: [{ email }],
        subject: '[M.I.T.Y REUNION] 예매 인증 메일',
        htmlContent: emailHtml(link),
      }),
    });
    if (!emailRes.ok) {
      const err = await emailRes.json();
      throw new Error('Brevo: ' + JSON.stringify(err));
    }

    res.json({ success: true });
  } catch (e) {
    console.error('emailAuth error', e);
    res.status(500).json({ error: 'Failed to send email', detail: e.message });
  }
});
