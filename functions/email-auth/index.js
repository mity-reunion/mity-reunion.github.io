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

const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'https://mity-reunion.github.io';
const SITE_URL = 'https://mity-reunion.github.io/booking.html';
const BREVO_API_KEY = process.env.BREVO_SMTP_KEY;
const SENDER_EMAIL = process.env.BREVO_USER || 'mityreunion@gmail.com';

const MAX_SEATS = 2;
// 유효한 좌석 ID 패턴: A-1~G-16, H-1~K-12, L-WC1, L-WC2, L-1, L-2
const VALID_SEAT_RE = /^([A-G]-([1-9]|1[0-6])|[H-K]-([1-9]|1[0-2])|L-(WC[12]|[12]))$/;

function setCors(res) {
  res.set('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
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
      <p style="font-size:1.2rem;font-weight:700;margin:0 0 8px;">로그인</p>
      <p style="font-size:0.85rem;color:rgba(255,255,255,0.55);margin:0 0 32px;">M.I.T.Y REUNION · 07.11 SAT 2PM</p>
      <p style="font-size:0.9rem;color:rgba(255,255,255,0.75);line-height:1.8;margin:0 0 32px;">
        아래 버튼을 클릭하면 예매 페이지로 이동합니다.<br>
        링크는 1시간 동안 유효합니다.
      </p>
      <a href="${link}" style="display:inline-block;padding:14px 32px;background:#fff;color:#000;font-weight:900;font-size:0.95rem;letter-spacing:0.1em;text-decoration:none;border-radius:4px;box-shadow:3px 3px 0 #cc2200;">인증하기</a>
      <p style="margin:32px 0 0;font-size:0.72rem;color:rgba(255,255,255,0.3);line-height:1.8;">
        본인이 요청하지 않은 경우 이 메일을 무시하세요.<br>
        수집된 개인정보는 공연 종료 후 즉시 폐기됩니다.
      </p>
    </td></tr>
  </table>
</body></html>`;
}

// ── 이메일 인증 링크 발송 ──
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

// ── 관리자 로그인 — 서버 측 검증 후 Firebase 커스텀 토큰 발급 ──
functions.http('adminLogin', async (req, res) => {
  setCors(res);
  if (req.method === 'OPTIONS') { res.status(204).send(''); return; }
  if (req.method !== 'POST') { res.status(405).json({ error: 'Method Not Allowed' }); return; }

  const { id, password } = req.body;
  if (!id || !password) {
    res.status(400).json({ error: 'id and password are required' });
    return;
  }

  try {
    const db = admin.firestore();
    const snap = await db.collection('admin').doc('credentials').get();
    if (!snap.exists) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    const accounts = snap.data().accounts || {};
    const pwHash = crypto.createHash('sha256').update(password).digest('hex');

    if (!accounts[id] || accounts[id] !== pwHash) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    // admin_{id} UID로 Firebase 커스텀 토큰 발급 (admin:true claim 포함)
    const uid = `admin_${id}`;
    const customToken = await admin.auth().createCustomToken(uid, { admin: true });

    res.json({ token: customToken, admin: id });
  } catch (e) {
    console.error('adminLogin error', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── 예매 취소 — 소유권 검증 + 원자적 트랜잭션 ──
functions.http('cancelBooking', async (req, res) => {
  setCors(res);
  if (req.method === 'OPTIONS') { res.status(204).send(''); return; }
  if (req.method !== 'POST') { res.status(405).json({ error: 'Method Not Allowed' }); return; }

  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }

  let decodedToken;
  try {
    decodedToken = await admin.auth().verifyIdToken(authHeader.slice(7));
  } catch (e) {
    res.status(401).json({ error: 'Invalid or expired token' });
    return;
  }

  const { ref } = req.body;
  if (!ref || typeof ref !== 'string') {
    res.status(400).json({ error: 'ref is required' });
    return;
  }

  const db = admin.firestore();

  try {
    await db.runTransaction(async (tx) => {
      const bookingRef = db.collection('bookings').doc(ref);
      const bookingSnap = await tx.get(bookingRef);
      if (!bookingSnap.exists) throw Object.assign(new Error(), { code: 'NOT_FOUND' });

      const booking = bookingSnap.data();
      if (booking.userId !== decodedToken.uid) throw Object.assign(new Error(), { code: 'FORBIDDEN' });
      if (booking.status !== 'confirmed') throw Object.assign(new Error(), { code: 'NOT_CONFIRMED' });

      const seatsToRelease = booking.seats || [];
      const reservedRef = db.collection('seats').doc('reserved');
      const reservedSnap = await tx.get(reservedRef);
      const currentReserved = reservedSnap.exists ? (reservedSnap.data().list || []) : [];

      tx.update(bookingRef, { status: 'cancelled' });
      tx.set(reservedRef, { list: currentReserved.filter(s => !seatsToRelease.includes(s)) });
    });

    res.json({ success: true });
  } catch (e) {
    if (e.code === 'NOT_FOUND')     { res.status(404).json({ error: 'Booking not found' }); return; }
    if (e.code === 'FORBIDDEN')     { res.status(403).json({ error: 'Forbidden' }); return; }
    if (e.code === 'NOT_CONFIRMED') { res.status(409).json({ error: 'Booking is not active' }); return; }
    console.error('cancelBooking error', e);
    res.status(500).json({ error: 'Failed to cancel booking' });
  }
});

// ── 좌석 변경 — 소유권 검증 + 가용성 확인 + 원자적 트랜잭션 ──
functions.http('changeBooking', async (req, res) => {
  setCors(res);
  if (req.method === 'OPTIONS') { res.status(204).send(''); return; }
  if (req.method !== 'POST') { res.status(405).json({ error: 'Method Not Allowed' }); return; }

  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }

  let decodedToken;
  try {
    decodedToken = await admin.auth().verifyIdToken(authHeader.slice(7));
  } catch (e) {
    res.status(401).json({ error: 'Invalid or expired token' });
    return;
  }

  const { ref, newSeats } = req.body;
  if (!ref || typeof ref !== 'string') {
    res.status(400).json({ error: 'ref is required' });
    return;
  }
  if (!Array.isArray(newSeats) || newSeats.length === 0 || newSeats.length > MAX_SEATS) {
    res.status(400).json({ error: `newSeats must be 1–${MAX_SEATS} items` });
    return;
  }
  if (!newSeats.every(s => typeof s === 'string' && VALID_SEAT_RE.test(s))) {
    res.status(400).json({ error: 'Invalid seat ID format' });
    return;
  }

  const db = admin.firestore();

  try {
    await db.runTransaction(async (tx) => {
      const bookingRef = db.collection('bookings').doc(ref);
      const bookingSnap = await tx.get(bookingRef);
      if (!bookingSnap.exists) throw Object.assign(new Error(), { code: 'NOT_FOUND' });

      const booking = bookingSnap.data();
      if (booking.userId !== decodedToken.uid) throw Object.assign(new Error(), { code: 'FORBIDDEN' });
      if (booking.status !== 'confirmed') throw Object.assign(new Error(), { code: 'NOT_CONFIRMED' });

      const oldSeats = booking.seats || [];
      const reservedRef = db.collection('seats').doc('reserved');
      const reservedSnap = await tx.get(reservedRef);
      const currentReserved = reservedSnap.exists ? (reservedSnap.data().list || []) : [];

      // 기존 좌석은 제외하고 새 좌석 충돌 확인
      const reservedWithoutOwn = currentReserved.filter(s => !oldSeats.includes(s));
      if (newSeats.some(s => reservedWithoutOwn.includes(s))) {
        throw Object.assign(new Error(), { code: 'SEAT_TAKEN' });
      }

      tx.update(bookingRef, { seats: newSeats, updatedAt: new Date().toISOString() });
      tx.set(reservedRef, { list: [...new Set([...reservedWithoutOwn, ...newSeats])] });
    });

    res.json({ success: true, seats: newSeats });
  } catch (e) {
    if (e.code === 'NOT_FOUND')     { res.status(404).json({ error: 'Booking not found' }); return; }
    if (e.code === 'FORBIDDEN')     { res.status(403).json({ error: 'Forbidden' }); return; }
    if (e.code === 'NOT_CONFIRMED') { res.status(409).json({ error: 'Booking is not active' }); return; }
    if (e.code === 'SEAT_TAKEN')    { res.status(409).json({ error: 'seat_taken' }); return; }
    console.error('changeBooking error', e);
    res.status(500).json({ error: 'Failed to change booking' });
  }
});

// ── 예매 생성 — 서버 측 검증 + 원자적 트랜잭션 ──
functions.http('createBooking', async (req, res) => {
  setCors(res);
  if (req.method === 'OPTIONS') { res.status(204).send(''); return; }
  if (req.method !== 'POST') { res.status(405).json({ error: 'Method Not Allowed' }); return; }

  // Firebase ID 토큰 검증
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }

  let decodedToken;
  try {
    decodedToken = await admin.auth().verifyIdToken(authHeader.slice(7));
  } catch (e) {
    res.status(401).json({ error: 'Invalid or expired token' });
    return;
  }

  const { seats, phone, email } = req.body;

  // 좌석 배열 검증
  if (!Array.isArray(seats) || seats.length === 0 || seats.length > MAX_SEATS) {
    res.status(400).json({ error: `seats must be 1–${MAX_SEATS} items` });
    return;
  }
  if (!seats.every(s => typeof s === 'string' && VALID_SEAT_RE.test(s))) {
    res.status(400).json({ error: 'Invalid seat ID format' });
    return;
  }

  const uid = decodedToken.uid;
  const db = admin.firestore();
  const refNum = 'MR' + Date.now().toString(36).toUpperCase();

  // 기존 예매 확인 (트랜잭션 외부 — 인덱스 쿼리는 트랜잭션 내 불가)
  const existingSnap = await db.collection('bookings')
    .where('userId', '==', uid)
    .where('status', '==', 'confirmed')
    .get();
  if (!existingSnap.empty) {
    res.status(409).json({ error: 'already_booked' });
    return;
  }

  if (phone) {
    const phoneSnap = await db.collection('bookings')
      .where('phone', '==', phone)
      .where('status', '==', 'confirmed')
      .get();
    if (!phoneSnap.empty) {
      res.status(409).json({ error: 'already_booked' });
      return;
    }
  }

  // 좌석 가용성 확인 + 예매 생성 (원자적 트랜잭션)
  try {
    await db.runTransaction(async (tx) => {
      const reservedRef = db.collection('seats').doc('reserved');
      const reservedSnap = await tx.get(reservedRef);
      const currentReserved = reservedSnap.exists ? (reservedSnap.data().list || []) : [];

      const conflict = seats.find(s => currentReserved.includes(s));
      if (conflict) throw Object.assign(new Error('SEAT_TAKEN'), { code: 'SEAT_TAKEN' });

      tx.set(db.collection('bookings').doc(refNum), {
        ref: refNum,
        userId: uid,
        userName: email || decodedToken.email || '',
        email: email || decodedToken.email || '',
        phone: phone || '',
        seats,
        amount: 0,
        createdAt: new Date().toISOString(),
        status: 'confirmed',
      });

      tx.set(reservedRef, { list: [...new Set([...currentReserved, ...seats])] });
    });

    res.json({ ref: refNum, seats });
  } catch (e) {
    if (e.code === 'SEAT_TAKEN') {
      res.status(409).json({ error: 'seat_taken' });
    } else {
      console.error('createBooking error', e);
      res.status(500).json({ error: 'Failed to create booking' });
    }
  }
});

// ── 관리자 배정석 취소 (본인 이메일 인증 필요) ──
functions.http('cancelAdminSeat', async (req, res) => {
  setCors(res);
  if (req.method === 'OPTIONS') { res.status(204).send(''); return; }
  if (req.method !== 'POST') { res.status(405).json({ error: 'Method Not Allowed' }); return; }

  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) { res.status(401).json({ error: 'Authentication required' }); return; }

  let decodedToken;
  try {
    decodedToken = await admin.auth().verifyIdToken(authHeader.slice(7));
  } catch(e) { res.status(401).json({ error: 'Invalid or expired token' }); return; }

  const email = (decodedToken.email || '').toLowerCase();
  if (!email) { res.status(400).json({ error: 'No email in token' }); return; }

  const db = admin.firestore();
  try {
    const blkRef = db.collection('seats').doc('adminBlocked');
    const blkSnap = await blkRef.get();
    if (!blkSnap.exists) { res.status(404).json({ error: 'no_reserved_seat' }); return; }

    const data = blkSnap.data();
    const list = data.list || [];
    const info = data.info || {};

    const seatIds = Object.keys(info).filter(k => (info[k].email || '').toLowerCase() === email);
    if (seatIds.length === 0) { res.status(404).json({ error: 'no_reserved_seat' }); return; }

    const newList = list.filter(s => !seatIds.includes(s));
    const newInfo = { ...info };
    seatIds.forEach(s => delete newInfo[s]);

    await blkRef.set({ list: newList, info: newInfo });
    res.json({ success: true });
  } catch(e) {
    console.error('cancelAdminSeat error', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── 관리자 배정석 변경 (본인 이메일 인증 필요) ──
functions.http('changeAdminSeat', async (req, res) => {
  setCors(res);
  if (req.method === 'OPTIONS') { res.status(204).send(''); return; }
  if (req.method !== 'POST') { res.status(405).json({ error: 'Method Not Allowed' }); return; }

  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) { res.status(401).json({ error: 'Authentication required' }); return; }

  let decodedToken;
  try {
    decodedToken = await admin.auth().verifyIdToken(authHeader.slice(7));
  } catch(e) { res.status(401).json({ error: 'Invalid or expired token' }); return; }

  const email = (decodedToken.email || '').toLowerCase();
  if (!email) { res.status(400).json({ error: 'No email in token' }); return; }

  const { newSeats } = req.body;
  if (!Array.isArray(newSeats) || newSeats.length === 0 || newSeats.length > MAX_SEATS) {
    res.status(400).json({ error: `newSeats must be 1–${MAX_SEATS} items` }); return;
  }
  if (!newSeats.every(s => typeof s === 'string' && VALID_SEAT_RE.test(s))) {
    res.status(400).json({ error: 'Invalid seat ID format' }); return;
  }

  const db = admin.firestore();
  try {
    const blkRef = db.collection('seats').doc('adminBlocked');
    const resRef = db.collection('seats').doc('reserved');
    const [blkSnap, resSnap] = await Promise.all([blkRef.get(), resRef.get()]);

    if (!blkSnap.exists) { res.status(404).json({ error: 'no_reserved_seat' }); return; }

    const blkData = blkSnap.data();
    const blkList = blkData.list || [];
    const blkInfo = blkData.info || {};
    const resList = resSnap.exists ? (resSnap.data().list || []) : [];

    const oldSeatIds = Object.keys(blkInfo).filter(k => (blkInfo[k].email || '').toLowerCase() === email);
    if (oldSeatIds.length === 0) { res.status(404).json({ error: 'no_reserved_seat' }); return; }

    const blkWithoutOld = blkList.filter(s => !oldSeatIds.includes(s));
    const conflict = newSeats.find(s => resList.includes(s) || blkWithoutOld.includes(s));
    if (conflict) { res.status(409).json({ error: 'seat_taken' }); return; }

    const sharedInfo = blkInfo[oldSeatIds[0]];
    const newBlkList = [...new Set([...blkWithoutOld, ...newSeats])];
    const newBlkInfo = { ...blkInfo };
    oldSeatIds.forEach(s => delete newBlkInfo[s]);
    newSeats.forEach(s => { newBlkInfo[s] = { ...sharedInfo }; });

    await blkRef.set({ list: newBlkList, info: newBlkInfo });
    res.json({ success: true, newSeats, newSeatId: newSeats[0], info: sharedInfo });
  } catch(e) {
    console.error('changeAdminSeat error', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── 예매 확인 (비인증 — 이메일 + 전화번호 뒷 4자리) ──
functions.http('checkBooking', async (req, res) => {
  setCors(res);
  if (req.method === 'OPTIONS') { res.status(204).send(''); return; }
  if (req.method !== 'POST') { res.status(405).json({ error: 'Method Not Allowed' }); return; }

  const { email, phoneSuffix } = req.body;
  if (!email || !phoneSuffix) {
    res.status(400).json({ error: 'email and phoneSuffix required' }); return;
  }
  if (!/^\d{4}$/.test(phoneSuffix)) {
    res.status(400).json({ error: 'phoneSuffix must be 4 digits' }); return;
  }

  const db = admin.firestore();
  try {
    const normalizedEmail = email.trim().toLowerCase();

    const snap = await db.collection('bookings')
      .where('email', '==', normalizedEmail)
      .get();

    const bookingDoc = snap.docs.find(d => d.data().status === 'confirmed');
    if (!bookingDoc) { res.status(404).json({ error: 'not_found' }); return; }
    const booking = bookingDoc.data();

    const storedPhone = (booking.phone || '').replace(/\D/g, '');
    if (!storedPhone || storedPhone.slice(-4) !== phoneSuffix) {
      res.status(401).json({ error: 'phone_mismatch' }); return;
    }

    // Firebase Auth 계정 존재 여부 확인 — 없으면 예매내역 삭제
    try {
      await admin.auth().getUserByEmail(normalizedEmail);
    } catch (authErr) {
      if (authErr.code === 'auth/user-not-found') {
        await db.runTransaction(async (tx) => {
          tx.delete(bookingDoc.ref);
          const reservedRef = db.collection('seats').doc('reserved');
          const reservedSnap = await tx.get(reservedRef);
          if (reservedSnap.exists) {
            const remaining = (reservedSnap.data().list || []).filter(s => !booking.seats.includes(s));
            tx.set(reservedRef, { list: remaining });
          }
        });
        res.status(404).json({ error: 'not_found' }); return;
      }
      throw authErr;
    }

    res.json({ ref: booking.ref, seats: booking.seats, phone: booking.phone });
  } catch (e) {
    console.error('checkBooking error', e);
    res.status(500).json({ error: 'Server error' });
  }
});
