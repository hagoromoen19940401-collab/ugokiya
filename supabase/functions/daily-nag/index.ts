/* 動きやー！ 毎日の煽り通知を配信する Edge Function
 *
 * 2つのモードがある：
 *   1. バッチ配信 : x-cron-secret ヘッダが CRON_SECRET と一致したとき。
 *                   push_targets() が返した「今送るべき相手」全員に送る。
 *   2. テスト配信 : ログイン中ユーザーのJWTで呼ばれたとき。
 *                   そのユーザー自身の端末にだけ、時刻や既送信に関係なく送る。
 *
 * Web Push の暗号処理は Web Crypto API だけで実装している（外部ライブラリなし）。
 * RFC 8291 §5 の試験値と一致することを確認済み。
 */

const SUPABASE_URL      = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE_KEY  = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const VAPID_PUBLIC_KEY  = Deno.env.get("VAPID_PUBLIC_KEY")!;
const VAPID_PRIVATE_KEY = Deno.env.get("VAPID_PRIVATE_KEY")!;
const VAPID_SUBJECT     = Deno.env.get("VAPID_SUBJECT") ?? "mailto:admin@example.com";
const CRON_SECRET       = Deno.env.get("CRON_SECRET") ?? "";

const enc = new TextEncoder();

/* ===================== base64url / バイト操作 ===================== */

function b64urlToBytes(s: string): Uint8Array {
  let t = String(s).replace(/-/g, "+").replace(/_/g, "/");
  t += "=".repeat((4 - (t.length % 4)) % 4);
  const raw = atob(t);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function bytesToB64url(b: ArrayBuffer | Uint8Array): string {
  const a = b instanceof Uint8Array ? b : new Uint8Array(b);
  let s = "";
  for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function concat(...arrs: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const a of arrs) n += a.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}

function rawPubToJwk(raw: Uint8Array): JsonWebKey {
  if (raw.length !== 65 || raw[0] !== 4) throw new Error("公開鍵の形式が不正");
  return {
    kty: "EC", crv: "P-256",
    x: bytesToB64url(raw.subarray(1, 33)),
    y: bytesToB64url(raw.subarray(33, 65)),
  };
}

async function hkdf(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number) {
  const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info }, key, length * 8);
  return new Uint8Array(bits);
}

/* ===================== RFC 8291 本文暗号化 ===================== */

async function encryptPayload(payload: string, p256dh: string, auth: string): Promise<Uint8Array> {
  const uaPublicRaw = b64urlToBytes(p256dh);
  const authSecret  = b64urlToBytes(auth);
  if (uaPublicRaw.length !== 65) throw new Error("p256dhが65バイトではない");
  if (authSecret.length !== 16)  throw new Error("authが16バイトではない");

  const pair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]) as CryptoKeyPair;
  const asPublicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));

  const uaPublic = await crypto.subtle.importKey(
    "jwk", rawPubToJwk(uaPublicRaw), { name: "ECDH", namedCurve: "P-256" }, false, []);

  const ecdhSecret = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "ECDH", public: uaPublic }, pair.privateKey, 256));

  const keyInfo = concat(enc.encode("WebPush: info"), new Uint8Array([0]), uaPublicRaw, asPublicRaw);
  const ikm = await hkdf(ecdhSecret, authSecret, keyInfo, 32);

  const salt  = crypto.getRandomValues(new Uint8Array(16));
  const cek   = await hkdf(ikm, salt, concat(enc.encode("Content-Encoding: aes128gcm"), new Uint8Array([0])), 16);
  const nonce = await hkdf(ikm, salt, concat(enc.encode("Content-Encoding: nonce"),     new Uint8Array([0])), 12);

  const padded = concat(enc.encode(payload), new Uint8Array([2]));  // 0x02 = 最終レコード
  const aesKey = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, tagLength: 128 }, aesKey, padded));

  // salt(16) || rs(4) || idlen(1) || as_public(65) || 暗号文
  const header = new Uint8Array(16 + 4 + 1 + 65);
  header.set(salt, 0);
  new DataView(header.buffer).setUint32(16, 4096, false);
  header[20] = asPublicRaw.length;
  header.set(asPublicRaw, 21);

  return concat(header, ct);
}

/* ===================== RFC 8292 VAPID ===================== */

async function vapidHeader(endpoint: string): Promise<string> {
  const aud = new URL(endpoint).origin;
  const head = bytesToB64url(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const body = bytesToB64url(enc.encode(JSON.stringify({
    aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: VAPID_SUBJECT,
  })));
  const signing = head + "." + body;

  const jwk = rawPubToJwk(b64urlToBytes(VAPID_PUBLIC_KEY)) as JsonWebKey & { d?: string };
  jwk.d = VAPID_PRIVATE_KEY;
  const key = await crypto.subtle.importKey(
    "jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);

  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(signing));
  return `vapid t=${signing}.${bytesToB64url(sig)}, k=${VAPID_PUBLIC_KEY}`;
}

/* ===================== 送信 ===================== */

interface Target {
  user_id: string; endpoint: string; p256dh: string; auth: string;
  local_day: string; minutes: number; goal: number;
}

const MSGS: [string, string][] = [
  ["動きやー！🏃", "今日まだ動いてへんやろ。10分だけでもええから動きや。"],
  ["まだ0分やで👀", "スマホ置いて、ちょっと歩いてこか。"],
  ["おい、運動🔥",  "『あとで』はだいたいやらんやつやで。今や。"],
  ["本日の運動、0分💀", "その記録、ほんまに残してええんか？"],
  ["立て。今や🫵",  "スクロールする元気あるなら歩けるで。"],
];

async function sendOne(t: Target): Promise<{ ok: boolean; status: number }> {
  const m = MSGS[Math.floor(Math.random() * MSGS.length)];
  const payload = JSON.stringify({
    title: m[0],
    body: t.minutes > 0
      ? `今日は${t.minutes}分。目標${t.goal}分まであとちょっとやで。`
      : m[1],
    tag: "ugokiya-daily",
  });

  const body = await encryptPayload(payload, t.p256dh, t.auth);
  const res = await fetch(t.endpoint, {
    method: "POST",
    headers: {
      "Authorization": await vapidHeader(t.endpoint),
      "Content-Encoding": "aes128gcm",
      "Content-Type": "application/octet-stream",
      "TTL": "86400",
      "Urgency": "normal",
    },
    body,
  });
  return { ok: res.ok, status: res.status };
}

/* ===================== Supabase REST ヘルパー ===================== */

function db(path: string, init: RequestInit = {}) {
  return fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
    ...init,
    headers: {
      "apikey": SERVICE_ROLE_KEY,
      "Authorization": `Bearer ${SERVICE_ROLE_KEY}`,
      "Content-Type": "application/json",
      ...(init.headers ?? {}),
    },
  });
}

async function dropSubscription(endpoint: string) {
  await db(`push_subscriptions?endpoint=eq.${encodeURIComponent(endpoint)}`, { method: "DELETE" });
}

async function bumpFailure(endpoint: string) {
  const r = await db(`push_subscriptions?endpoint=eq.${encodeURIComponent(endpoint)}&select=fail_count`);
  const rows = await r.json();
  const n = (rows?.[0]?.fail_count ?? 0) + 1;
  await db(`push_subscriptions?endpoint=eq.${encodeURIComponent(endpoint)}`, {
    method: "PATCH", body: JSON.stringify({ fail_count: n }),
  });
}

async function markOk(endpoint: string) {
  await db(`push_subscriptions?endpoint=eq.${encodeURIComponent(endpoint)}`, {
    method: "PATCH",
    body: JSON.stringify({ fail_count: 0, last_ok_at: new Date().toISOString() }),
  });
}

async function markPushed(userId: string, day: string) {
  await db(`settings?user_id=eq.${userId}`, {
    method: "PATCH", body: JSON.stringify({ last_push_day: day }),
  });
}

/* 送信して結果に応じて後始末する。送れたら true */
async function deliver(t: Target): Promise<boolean> {
  try {
    const { ok, status } = await sendOne(t);
    if (ok) { await markOk(t.endpoint); return true; }
    // 404/410 は「その宛先はもう存在しない」＝端末側で購読が消えた
    if (status === 404 || status === 410) { await dropSubscription(t.endpoint); return false; }
    await bumpFailure(t.endpoint);
    console.error("送信失敗", status, t.endpoint.slice(0, 60));
    return false;
  } catch (e) {
    await bumpFailure(t.endpoint);
    console.error("送信中の例外", String(e), t.endpoint.slice(0, 60));
    return false;
  }
}

/* ===================== エントリポイント ===================== */

Deno.serve(async (req) => {
  const json = (b: unknown, s = 200) =>
    new Response(JSON.stringify(b), { status: s, headers: { "Content-Type": "application/json" } });

  if (req.method === "OPTIONS") {
    return new Response("ok", {
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-cron-secret",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
      },
    });
  }

  for (const [k, v] of Object.entries({ SUPABASE_URL, SERVICE_ROLE_KEY, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY })) {
    if (!v) return json({ error: `環境変数 ${k} が未設定` }, 500);
  }

  const cors = { "Access-Control-Allow-Origin": "*" };
  const cronSecret = req.headers.get("x-cron-secret") ?? "";

  /* --- モード1: バッチ配信 --- */
  if (CRON_SECRET && cronSecret === CRON_SECRET) {
    const r = await db("rpc/push_targets", { method: "POST", body: "{}" });
    if (!r.ok) return json({ error: "push_targets呼び出し失敗", detail: await r.text() }, 500);
    const targets: Target[] = await r.json();

    let sent = 0;
    const doneUsers = new Set<string>();
    for (const t of targets) {
      if (await deliver(t)) {
        sent++;
        if (!doneUsers.has(t.user_id)) {
          await markPushed(t.user_id, t.local_day);
          doneUsers.add(t.user_id);
        }
      }
    }
    return new Response(
      JSON.stringify({ mode: "cron", targets: targets.length, sent, users: doneUsers.size }),
      { headers: { "Content-Type": "application/json", ...cors } });
  }

  /* --- モード2: テスト配信（本人のJWTが要る） --- */
  const authz = req.headers.get("Authorization") ?? "";
  const jwt = authz.startsWith("Bearer ") ? authz.slice(7) : "";
  if (!jwt) return json({ error: "認証が要る" }, 401);

  const who = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
    headers: { "apikey": SERVICE_ROLE_KEY, "Authorization": `Bearer ${jwt}` },
  });
  if (!who.ok) return json({ error: "トークンが無効" }, 401);
  const user = await who.json();
  const userId: string = user.id;

  const sr = await db(`push_subscriptions?user_id=eq.${userId}&select=endpoint,p256dh,auth`);
  const subs = await sr.json();
  if (!Array.isArray(subs) || subs.length === 0) {
    return new Response(JSON.stringify({ error: "この人の購読が登録されてへん" }),
      { status: 404, headers: { "Content-Type": "application/json", ...cors } });
  }

  let sent = 0;
  for (const s of subs) {
    const ok = await deliver({
      user_id: userId, endpoint: s.endpoint, p256dh: s.p256dh, auth: s.auth,
      local_day: "", minutes: 0, goal: 20,
    });
    if (ok) sent++;
  }
  return new Response(JSON.stringify({ mode: "test", subscriptions: subs.length, sent }),
    { headers: { "Content-Type": "application/json", ...cors } });
});
