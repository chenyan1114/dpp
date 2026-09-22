/* ISO 證書 → VC v2.0 Demo：真 Ed25519 did:key、DataIntegrityProof 簽名/驗證，零依賴離線可用。 */
"use strict";

const $ = (id) => document.getElementById(id);

/* ---------- base58btc ---------- */
const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58btcEncode(bytes) {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  let num = 0n;
  for (const b of bytes) num = (num << 8n) | BigInt(b);
  let out = "";
  while (num > 0n) {
    const mod = num % 58n;
    out = B58_ALPHABET[Number(mod)] + out;
    num = num / 58n;
  }
  return "1".repeat(zeros) + out;
}

function didKeyFromEd25519Pubkey(pub32) {
  if (pub32.length !== 32) throw new Error("pubkey 必須是 32 bytes");
  const prefixed = new Uint8Array(34);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(pub32, 2);
  return "did:key:z" + base58btcEncode(prefixed);
}

function base58btcDecode(str) {
  let num = 0n;
  for (const ch of str) {
    const i = B58_ALPHABET.indexOf(ch);
    if (i < 0) throw new Error("base58 非法字元: " + ch);
    num = num * 58n + BigInt(i);
  }
  const tail = [];
  while (num > 0n) {
    tail.unshift(Number(num & 0xffn));
    num >>= 8n;
  }
  let zeros = 0;
  while (zeros < str.length && str[zeros] === "1") zeros++;
  const out = new Uint8Array(zeros + tail.length);
  out.set(tail, zeros);
  return out;
}

function decodeDidKey(did) {
  const prefix = "did:key:z";
  if (typeof did !== "string" || !did.startsWith(prefix)) throw new Error("不是 did:key:z 開頭");
  const raw = base58btcDecode(did.slice(prefix.length));
  if (raw.length !== 34) throw new Error("解碼後長度應為 34 bytes，實際 " + raw.length);
  if (raw[0] !== 0xed || raw[1] !== 0x01) throw new Error("multicodec 前綴不是 0xED01（非 Ed25519）");
  return raw.slice(2);
}

function isEd25519PointOnCurve(compressed32) {
  const b = Uint8Array.from(compressed32);
  b[31] &= 0x7f;
  let y = 0n;
  for (let i = 0; i < 32; i++) y |= BigInt(b[i]) << (8n * BigInt(i));
  if (y >= P) return { ok: false, reason: "y 超出有限體範圍" };
  const y2 = (y * y) % P;
  const num = (y2 - 1n + P) % P;
  const den = (D * y2 + 1n) % P;
  if (den === 0n) return { ok: false, reason: "分母為 0（非法點）" };
  const x2 = (num * modPow(den, P - 2n, P)) % P;
  if (x2 === 0n) return y === 1n ? { ok: true } : { ok: false, reason: "x²=0 但 y≠1" };
  if (modPow(x2, (P - 1n) / 2n, P) !== 1n) return { ok: false, reason: "曲線方程式無解（不在曲線上）" };
  return { ok: true };
}

/* ---------- Ed25519 純 JS fallback（BigInt） ---------- */
const P = (1n << 255n) - 19n;
const D = ((-121665n * modPow(121666n, P - 2n, P)) % P + P) % P;
const D2 = (2n * D) % P;
const BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202n;
const BY = 46316835694926478169428394003475163141307993866256225615783033603165251855960n;

function modPow(base, exp, mod) {
  let r = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) r = (r * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return r;
}

function pointAdd(p, q) {
  const [X1, Y1, Z1, T1] = p;
  const [X2, Y2, Z2, T2] = q;
  const A = ((Y1 - X1) * (Y2 - X2)) % P;
  const B = ((Y1 + X1) * (Y2 + X2)) % P;
  const C = (((T1 * D2) % P) * T2) % P;
  const Dd = ((Z1 * 2n) * Z2) % P;
  const E = B - A, F = Dd - C, G = Dd + C, H = B + A;
  const mod = (x) => ((x % P) + P) % P;
  return [mod(E * F), mod(G * H), mod(F * G), mod(E * H)];
}

function scalarMultBase(scalar) {
  let Q = [0n, 1n, 1n, 0n];
  let cur = [BX, BY, 1n, (BX * BY) % P];
  let s = scalar;
  while (s > 0n) {
    if (s & 1n) Q = pointAdd(Q, cur);
    cur = pointAdd(cur, cur);
    s >>= 1n;
  }
  return Q;
}

function encodeEdPoint(X, Y, Z) {
  const invZ = modPow(Z, P - 2n, P);
  const x = (X * invZ) % P;
  const y = (Y * invZ) % P;
  const out = new Uint8Array(32);
  let yy = y;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(yy & 0xffn);
    yy >>= 8n;
  }
  if (x & 1n) out[31] |= 0x80;
  return out;
}

async function sha512(data) {
  const buf = await crypto.subtle.digest("SHA-512", data);
  return new Uint8Array(buf);
}

async function ed25519PubkeyFromSeedPureJS(seed32) {
  const h = await sha512(seed32);
  const clamped = h.slice(0, 32);
  clamped[0] &= 248;
  clamped[31] &= 63;
  clamped[31] |= 64;
  let scalar = 0n;
  for (let i = 0; i < 32; i++) scalar |= BigInt(clamped[i]) << (8n * BigInt(i));
  const [X, Y, Z] = scalarMultBase(scalar);
  return encodeEdPoint(X, Y, Z);
}

/* ---------- DID 生成（原生優先，fallback 純 JS） ---------- */
let lastKeyMethod = "";
let issuerDid = "", holderDid = "";
let issuerKeys = null, holderKeys = null;

async function generateOneDidKey() {
  try {
    if (crypto.subtle.generateKey) {
      const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
      if (kp && kp.publicKey) {
        const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
        if (raw.length === 32) {
          return { did: didKeyFromEd25519Pubkey(raw), method: "WebCrypto 原生 Ed25519", kind: "native", keypair: kp, pub: raw };
        }
      }
    }
  } catch (_) {}
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  const pub = await ed25519PubkeyFromSeedPureJS(seed);
  return { did: didKeyFromEd25519Pubkey(pub), method: "內嵌純 JS Ed25519（CSPRNG seed + SHA-512 + 曲線純量乘）", kind: "purejs", seed, pub };
}

/* ---------- JCS 正規化（RFC 8785，eddsa-jcs-2022 轉換步驟用） ---------- */
function jcsQuote(s) {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) out += '\\"';
    else if (c === 0x5c) out += "\\\\";
    else if (c === 0x08) out += "\\b";
    else if (c === 0x0c) out += "\\f";
    else if (c === 0x0a) out += "\\n";
    else if (c === 0x0d) out += "\\r";
    else if (c === 0x09) out += "\\t";
    else if (c < 0x20) out += "\\u00" + c.toString(16).padStart(2, "0");
    else if (c >= 0xd800 && c <= 0xdbff) {
      const n = s.charCodeAt(i + 1);
      if (n >= 0xdc00 && n <= 0xdfff) { out += s[i] + s[i + 1]; i++; }
      else throw new Error("JCS 不允許孤立 surrogate");
    }
    else if (c >= 0xdc00 && c <= 0xdfff) throw new Error("JCS 不允許孤立 surrogate");
    else out += s[i];
  }
  return out + '"';
}

function jcsCanonicalize(value) {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("JCS 不允許 NaN/Infinity");
    return String(value);
  }
  if (typeof value === "string") return jcsQuote(value);
  if (Array.isArray(value)) return "[" + value.map(jcsCanonicalize).join(",") + "]";
  if (typeof value === "object") {
    const parts = [];
    for (const k of Object.keys(value).sort()) {
      const v = value[k];
      if (v === undefined || typeof v === "function" || typeof v === "symbol") {
        throw new Error("JCS 不允許 undefined/function/symbol");
      }
      parts.push(jcsQuote(k) + ":" + jcsCanonicalize(v));
    }
    return "{" + parts.join(",") + "}";
  }
  throw new Error("JCS 不支援型別: " + typeof value);
}

/* ---------- DataIntegrityProof（eddsa-jcs-2022）簽名與驗證 ---------- */
const ED_L = (1n << 252n) + 27742317777372353535851937790883648493n;

function concatBytes(...arrs) {
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let p = 0;
  for (const a of arrs) { out.set(a, p); p += a.length; }
  return out;
}

async function sha256Bytes(data) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

function leToBigInt(le) {
  let n = 0n;
  for (let i = 0; i < le.length; i++) n |= BigInt(le[i]) << (8n * BigInt(i));
  return n;
}

function bigIntToLe32(n) {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) { out[i] = Number(n & 0xffn); n >>= 8n; }
  return out;
}

function scalarMultPoint(Pt, scalar) {
  let Q = [0n, 1n, 1n, 0n];
  let cur = Pt;
  let s = scalar;
  while (s > 0n) {
    if (s & 1n) Q = pointAdd(Q, cur);
    cur = pointAdd(cur, cur);
    s >>= 1n;
  }
  return Q;
}

function decodePointCompressed(enc) {
  const b = Uint8Array.from(enc);
  if (b.length !== 32) throw new Error("壓縮點需為 32 bytes");
  const bit = (b[31] >> 7) & 1;
  b[31] &= 0x7f;
  const y = leToBigInt(b);
  if (y >= P) throw new Error("點座標 y 超出有限體");
  const y2 = (y * y) % P;
  const den = (D * y2 + 1n) % P;
  if (den === 0n) throw new Error("非法點（分母為 0）");
  const x2 = (((y2 - 1n + P) % P) * modPow(den, P - 2n, P)) % P;
  let x = modPow(x2, (P + 3n) / 8n, P);
  if (((x * x - x2) % P + P) % P !== 0n) x = (x * modPow(2n, (P - 1n) / 4n, P)) % P;
  if ((((x * x - x2) % P) + P) % P !== 0n) throw new Error("點不在曲線上");
  if ((x & 1n) !== BigInt(bit)) x = P - x;
  return [x, y, 1n, (x * y) % P];
}

function clampScalar(h32) {
  const c = Uint8Array.from(h32.slice(0, 32));
  c[0] &= 248; c[31] &= 63; c[31] |= 64;
  return leToBigInt(c);
}

async function eddsaSignPure(seed32, msg) {
  const h = await sha512(seed32);
  const a = clampScalar(h.slice(0, 32));
  const prefix = h.slice(32, 64);
  const r = leToBigInt(await sha512(concatBytes(prefix, msg))) % ED_L;
  const Renc = encodeEdPoint(...scalarMultBase(r));
  const Aenc = encodeEdPoint(...scalarMultBase(a));
  const k = leToBigInt(await sha512(concatBytes(Renc, Aenc, msg))) % ED_L;
  const S = (r + k * a) % ED_L;
  return concatBytes(Renc, bigIntToLe32(S));
}

async function eddsaVerifyPure(pub32, msg, sig64) {
  try {
    if (!(sig64 instanceof Uint8Array) || sig64.length !== 64) return false;
    const Renc = sig64.slice(0, 32);
    const S = leToBigInt(sig64.slice(32, 64));
    if (S >= ED_L) return false;
    const Rpt = decodePointCompressed(Renc);
    const Apt = decodePointCompressed(pub32);
    const k = leToBigInt(await sha512(concatBytes(Renc, Uint8Array.from(pub32), msg))) % ED_L;
    const lhs = scalarMultBase(S);
    const rhs = pointAdd(Rpt, scalarMultPoint(Apt, k));
    const norm = ([X, Y, Z]) => { const iz = modPow(Z, P - 2n, P); return [(X * iz) % P, (Y * iz) % P]; };
    const [lx, ly] = norm(lhs), [rx, ry] = norm(rhs);
    return lx === rx && ly === ry;
  } catch (_) {
    return false;
  }
}

async function edSign(hashData, keys) {
  if (keys.kind === "native") {
    return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, keys.keypair.privateKey, hashData));
  }
  return eddsaSignPure(keys.seed, hashData);
}

async function edVerifyMsg(hashData, sig64, pub32) {
  try {
    const pubKey = await crypto.subtle.importKey("raw", pub32, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, pubKey, sig64, hashData);
  } catch (_) {}
  return eddsaVerifyPure(pub32, hashData, sig64);
}

async function createDataIntegrityProof(unsignedVc, keys, createdIso) {
  if (!keys || (keys.kind !== "native" && keys.kind !== "purejs")) {
    throw new Error("缺少 issuer 私鑰材料，請重新生成 DID:key（清除後需重走 生成→組 VC→簽名）");
  }
  if (isNaN(Date.parse(createdIso))) throw new Error("created 非法時間");
  if (unsignedVc.proof !== undefined) throw new Error("文件已含 proof，請重新生成未簽名的 VC 再簽");
  const fingerprint = keys.did.slice("did:key:".length);
  const proofOptions = {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    created: createdIso,
    verificationMethod: keys.did + "#" + fingerprint,
    proofPurpose: "assertionMethod",
    "@context": unsignedVc["@context"],
  };
  const te = new TextEncoder();
  const proofConfigHash = await sha256Bytes(te.encode(jcsCanonicalize(proofOptions)));
  const docHash = await sha256Bytes(te.encode(jcsCanonicalize(unsignedVc)));
  const sig = await edSign(concatBytes(proofConfigHash, docHash), keys);
  return { ...proofOptions, proofValue: "z" + base58btcEncode(sig) };
}

async function verifyDataIntegrityProof(signedVc) {
  const fails = [], warns = [], passes = [];
  const proof = signedVc.proof;
  if (!proof || typeof proof !== "object" || Array.isArray(proof)) {
    return { verified: false, fails: ["缺少 proof 物件（本 demo 只支援單一 proof）"], warns, passes };
  }
  if (proof.type !== "DataIntegrityProof") fails.push('proof.type 需為 "DataIntegrityProof"');
  else passes.push("proof.type 正確");
  if (proof.cryptosuite !== "eddsa-jcs-2022") fails.push('proof.cryptosuite 需為 "eddsa-jcs-2022"');
  else passes.push("cryptosuite 為 eddsa-jcs-2022");
  if (proof.proofPurpose !== "assertionMethod") warns.push("proofPurpose 不是 assertionMethod（本 demo 預期 assertionMethod）");
  else passes.push("proofPurpose 為 assertionMethod");
  if (typeof proof.created !== "string" || isNaN(Date.parse(proof.created))) fails.push("proof.created 非法時間");
  else passes.push("proof.created 為合法時間");
  let sig = null;
  if (typeof proof.proofValue !== "string" || !proof.proofValue.startsWith("z")) {
    fails.push("proofValue 需為 z 開頭的 multibase base58btc");
  } else {
    try {
      sig = base58btcDecode(proof.proofValue.slice(1));
      if (sig.length !== 64) fails.push("簽名長度應為 64 bytes，實際 " + sig.length);
      else passes.push("proofValue 解碼為 64-byte 簽名");
    } catch (e) { fails.push("proofValue 解碼失敗：" + e.message); }
  }
  let pub = null;
  const vm = proof.verificationMethod;
  if (typeof vm !== "string" || !vm.includes("#")) {
    fails.push("verificationMethod 需為 did:key 加 #fragment 形式");
  } else {
    const base = vm.slice(0, vm.indexOf("#"));
    const frag = vm.slice(vm.indexOf("#") + 1);
    try {
      pub = decodeDidKey(base);
      const c = isEd25519PointOnCurve(pub);
      if (!c.ok) fails.push("verificationMethod 公鑰非法：" + c.reason);
      else passes.push("verificationMethod 的 did:key 解碼成功");
    } catch (e) { fails.push("verificationMethod DID 非法：" + e.message); }
    if (base !== signedVc.issuer) fails.push("verificationMethod 的 DID 與 VC issuer 不一致");
    else passes.push("verificationMethod 對應 VC issuer");
    if (frag !== base.slice("did:key:".length)) warns.push("verificationMethod fragment 與 did:key 指紋不一致（互通性警告）");
    else passes.push("verificationMethod fragment 正確");
  }
  if (fails.length) return { verified: false, fails, warns, passes };
  const proofOptions = { ...proof };
  delete proofOptions.proofValue;
  const unsecured = { ...signedVc };
  delete unsecured.proof;
  if (proofOptions["@context"] !== undefined) {
    const pc = Array.isArray(proofOptions["@context"]) ? proofOptions["@context"] : [proofOptions["@context"]];
    const dc = Array.isArray(unsecured["@context"]) ? unsecured["@context"] : [unsecured["@context"]];
    if (!(pc.length <= dc.length && pc.every((v, i) => dc[i] === v))) {
      fails.push("文件 @context 與 proof 內 @context 副本前綴不一致");
      return { verified: false, fails, warns, passes };
    }
    passes.push("@context 前綴一致");
    unsecured["@context"] = proofOptions["@context"];
  }
  const te = new TextEncoder();
  const proofConfigHash = await sha256Bytes(te.encode(jcsCanonicalize(proofOptions)));
  const docHash = await sha256Bytes(te.encode(jcsCanonicalize(unsecured)));
  const ok = await edVerifyMsg(concatBytes(proofConfigHash, docHash), sig, pub);
  if (ok) passes.push("Ed25519 簽名驗證通過（未竄改 ✓ 確為 issuer 私鑰所簽 ✓）");
  else fails.push("簽名驗證失敗：文件曾被竄改，或非 issuer 私鑰所簽");
  return { verified: ok && fails.length === 0, fails, warns, passes };
}

/* ---------- VC v2.0 組裝 ---------- */
function toValidUntilDateTime(v) {
  v = (v || "").trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(v)) return v + "T00:00:00Z";
  return v;
}

function buildVc() {
  const standard = $("inStandard").value.trim();
  const number = $("inNumber").value.trim();
  const scope = $("inScope").value.trim();
  const holderName = $("inHolderName").value.trim();
  const validUntil = toValidUntilDateTime($("inValidUntil").value);
  if (!issuerDid || !holderDid) throw new Error("請先生成 issuer + holder DID:key");
  if (!standard || !number || !scope || !validUntil) throw new Error("ISO 欄位不可空白");
  const subject = {
    id: holderDid,
    certificationStandard: standard,
    certificateNumber: number,
    scope: scope,
  };
  if (holderName) subject.name = holderName;
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: "urn:uuid:" + crypto.randomUUID(),
    type: ["VerifiableCredential", "IsoCertificationCredential"],
    issuer: issuerDid,
    validFrom: new Date().toISOString(),
    validUntil: validUntil,
    credentialSubject: subject,
  };
}

function verifyVc(vc, form) {
  const fails = [], warns = [], passes = [], infos = [];
  if (!vc || typeof vc !== "object" || Array.isArray(vc)) {
    return { fails: ["VC 不是一個 JSON 物件"], warns, passes, infos };
  }
  if (Array.isArray(vc["@context"]) && vc["@context"].includes("https://www.w3.org/ns/credentials/v2")) {
    passes.push("@context 含 W3C v2");
  } else {
    fails.push("@context 需包含 https://www.w3.org/ns/credentials/v2");
  }
  if (Array.isArray(vc.type) && vc.type.includes("VerifiableCredential")) {
    passes.push("type 含 VerifiableCredential");
  } else {
    fails.push('type 需包含 "VerifiableCredential"');
  }
  if (Array.isArray(vc.type) && vc.type.includes("IsoCertificationCredential")) {
    passes.push("type 含 IsoCertificationCredential");
  } else {
    warns.push('建議 type 加上 "IsoCertificationCredential"');
  }
  const uuidRe = /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (uuidRe.test(String(vc.id || ""))) {
    passes.push("id 為合法 urn:uuid");
  } else if (String(vc.id || "").startsWith("urn:uuid:")) {
    warns.push("id 有 urn:uuid: 前綴但 UUID 格式不標準");
  } else {
    fails.push("id 需為 urn:uuid:<uuid> 格式");
  }
  let issuerPub = null, holderPub = null;
  try {
    issuerPub = decodeDidKey(vc.issuer);
    const c = isEd25519PointOnCurve(issuerPub);
    if (c.ok) passes.push("issuer did:key 解碼成功，公鑰在 Ed25519 曲線上");
    else fails.push("issuer 公鑰非法：" + c.reason);
  } catch (e) {
    fails.push("issuer DID 非法：" + e.message);
  }
  const subj = vc.credentialSubject || {};
  try {
    holderPub = decodeDidKey(subj.id);
    const c = isEd25519PointOnCurve(holderPub);
    if (c.ok) passes.push("credentialSubject.id did:key 解碼成功，公鑰在曲線上");
    else fails.push("holder 公鑰非法：" + c.reason);
  } catch (e) {
    fails.push("credentialSubject.id DID 非法：" + e.message);
  }
  if (issuerPub && holderPub) {
    if (vc.issuer !== subj.id) passes.push("issuer 與 holder 為不同 DID（非自簽）");
    else warns.push("issuer 與 holder 相同（自簽憑證，demo 正常應為不同）");
  }
  for (const k of ["certificationStandard", "certificateNumber", "scope"]) {
    if (subj[k] && String(subj[k]).trim()) passes.push("claim 有 " + k);
    else fails.push("缺 claim: " + k);
  }
  const from = Date.parse(vc.validFrom), until = Date.parse(vc.validUntil);
  if (!isNaN(from)) passes.push("validFrom 為合法時間");
  else fails.push("validFrom 非法或缺失（v2 必備）");
  if (!isNaN(until)) passes.push("validUntil 為合法時間");
  else fails.push("validUntil 非法或缺失");
  if (!isNaN(from) && !isNaN(until)) {
    if (until > from) passes.push("validUntil 晚於 validFrom");
    else fails.push("validUntil 應晚於 validFrom");
  }
  if (form) {
    const cmp = [
      ["certificationStandard", subj.certificationStandard, form.standard],
      ["certificateNumber", subj.certificateNumber, form.number],
      ["scope", subj.scope, form.scope],
    ];
    for (const [k, a, b] of cmp) {
      if (String(a ?? "") === String(b ?? "")) passes.push(`VC 的 ${k} 與表單一致`);
      else warns.push(`VC 的 ${k} 與目前表單不同（生成後改了表單？以 VC 內容為準）`);
    }
    if (form.validUntil && String(vc.validUntil || "").startsWith(String(form.validUntil).slice(0, 10))) {
      passes.push("validUntil 日期與表單一致");
    } else if (form.validUntil) {
      warns.push("validUntil 與目前表單日期不同");
    }
    if (form.issuerDid && vc.issuer !== form.issuerDid) warns.push("issuer 與頁面上目前的 DID 不同（生成 VC 後重按了生成？）");
    if (form.holderDid && subj.id !== form.holderDid) warns.push("holder 與頁面上目前的 DID 不同（生成 VC 後重按了生成？）");
  }
  if ("proof" in vc) infos.push("含 proof：按驗證會加做密碼學驗證");
  else infos.push("無 proof（unsigned）：以上只驗結構＋DID 解碼，無法做發證者密碼學驗證");
  return { fails, warns, passes, infos };
}

/* ---------- UI 接線 ---------- */
$("btnGen").addEventListener("click", async () => {
  $("btnGen").disabled = true;
  $("keyMethod").textContent = "生成中…";
  try {
    const a = await generateOneDidKey();
    const b = await generateOneDidKey();
    issuerDid = a.did;
    holderDid = b.did;
    issuerKeys = a;
    holderKeys = b;
    lastKeyMethod = a.method.startsWith("WebCrypto") && b.method.startsWith("WebCrypto")
      ? "WebCrypto 原生 Ed25519"
      : "內嵌純 JS Ed25519（部分或全部）";
    $("issuerDid").textContent = issuerDid;
    $("holderDid").textContent = holderDid;
    $("keyMethod").textContent = "生成方式：" + lastKeyMethod + " · 兩把已確認不同：" + (issuerDid !== holderDid ? "是" : "否（極不可能，請重按）") + " · issuer 私鑰已留存記憶體，可簽名";
  } catch (e) {
    $("keyMethod").textContent = "生成失敗：" + e.message;
  } finally {
    $("btnGen").disabled = false;
  }
});

$("btnClearKeys").addEventListener("click", () => {
  issuerDid = holderDid = "";
  issuerKeys = holderKeys = null;
  $("issuerDid").textContent = "尚未生成";
  $("holderDid").textContent = "尚未生成";
  $("keyMethod").textContent = "—";
});

$("btnIssue").addEventListener("click", () => {
  try {
    const vc = buildVc();
    $("vcOut").textContent = JSON.stringify(vc, null, 2);
    const r = verifyVc(vc, null);
    $("vcCheck").innerHTML = r.fails.length === 0
      ? '<span class="ok">✓ 結構檢查通過（v2.0 必備欄位齊全，未簽名教學用）</span>'
      : '<span style="color:#dc2626">✗ ' + r.fails.join("；") + "</span>";
    $("vcVerify").innerHTML = "";
    setBadge(false);
  } catch (e) {
    $("vcOut").textContent = "生成失敗：" + e.message;
    $("vcCheck").textContent = "";
  }
});

function setBadge(signed) {
  const b = $("signBadge");
  if (!b) return;
  b.textContent = signed ? "SIGNED · eddsa-jcs-2022" : "UNSIGNED · 教學用";
  b.style.background = signed ? "#16a34a" : "#f59e0b";
  b.style.color = signed ? "white" : "#111";
}

$("btnSign").addEventListener("click", async () => {
  $("btnSign").disabled = true;
  try {
    const vc = JSON.parse($("vcOut").textContent);
    if (!issuerKeys || issuerKeys.did !== vc.issuer) {
      throw new Error("頁面私鑰與此 VC 的 issuer 不符（重按過生成？）。請按順序重走：生成 DID → 生成 VC → 簽名，中途不要重按生成。");
    }
    const proof = await createDataIntegrityProof(vc, issuerKeys, new Date().toISOString());
    const signed = { ...vc, proof };
    $("vcOut").textContent = JSON.stringify(signed, null, 2);
    $("vcCheck").innerHTML = '<span class="ok">✓ 已簽名：DataIntegrityProof / eddsa-jcs-2022，可按「驗證這份 VC」做密碼學驗證。</span>';
    $("vcVerify").innerHTML = "";
    setBadge(true);
  } catch (e) {
    $("vcCheck").innerHTML = '<span style="color:#dc2626">簽名失敗：' + escHtml(e.message) + "</span>";
  } finally {
    $("btnSign").disabled = false;
  }
});

$("btnCopy").addEventListener("click", async () => {
  const t = $("vcOut").textContent;
  try {
    await navigator.clipboard.writeText(t);
    $("vcCheck").textContent = "已複製到剪貼簿。";
  } catch {
    const ta = document.createElement("textarea");
    ta.value = t;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
    $("vcCheck").textContent = "已複製到剪貼簿（fallback）。";
  }
});

$("btnDownload").addEventListener("click", () => {
  const blob = new Blob([$("vcOut").textContent], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "vc.json";
  a.click();
  URL.revokeObjectURL(a.href);
});

function escHtml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

$("btnVerify").addEventListener("click", async () => {
  let vc;
  try {
    vc = JSON.parse($("vcOut").textContent);
  } catch {
    $("vcVerify").innerHTML = '<span style="color:#dc2626">請先生成或上傳一份 VC，再驗證。</span>';
    return;
  }
  $("vcVerify").innerHTML = "驗證中…";
  const form = {
    standard: $("inStandard").value.trim(),
    number: $("inNumber").value.trim(),
    scope: $("inScope").value.trim(),
    validUntil: $("inValidUntil").value.trim(),
    issuerDid, holderDid,
  };
  const r = verifyVc(vc, form);
  if (vc && typeof vc === "object" && vc.proof !== undefined) {
    try {
      const pr = await verifyDataIntegrityProof(vc);
      r.passes.push(...pr.passes.map((t) => "[簽名] " + t));
      r.warns.push(...pr.warns.map((t) => "[簽名] " + t));
      r.fails.push(...pr.fails.map((t) => "[簽名] " + t));
    } catch (e) {
      r.fails.push("[簽名] 驗證過程出錯：" + e.message);
    }
  }
  const line = (sym, color, t) => `<div style="color:${color}">${sym} ${escHtml(t)}</div>`;
  let html = "";
  for (const t of r.fails) html += line("✗", "#dc2626", t);
  for (const t of r.warns) html += line("⚠", "#b45309", t);
  for (const t of r.passes) html += line("✓", "#16a34a", t);
  for (const t of r.infos) html += line("ℹ", "#6b7280", t);
  const summary = r.fails.length === 0
    ? `<p><strong style="color:#16a34a">驗證通過：${r.passes.length} 項檢查全過${r.warns.length ? `（另 ${r.warns.length} 項提醒）` : ""}</strong></p>`
    : `<p><strong style="color:#dc2626">驗證失敗：${r.fails.length} 項錯誤</strong></p>`;
  $("vcVerify").innerHTML = summary + html;
});

$("btnSample").addEventListener("click", async () => {
  try {
    const res = await fetch("./sample-iso-cert.json");
    if (!res.ok) throw new Error("HTTP " + res.status);
    const j = await res.json();
    fillIsoForm(j);
    $("fileStatus").textContent = "已載入 sample-iso-cert.json。";
  } catch (e) {
    $("fileStatus").textContent = "fetch 失敗（file:// 直接開啟會擋 fetch），已保留表單預設範例值。請用 python -m http.server 開啟，或用「從 JSON 檔匯入」。";
  }
});

function fillIsoForm(j) {
  if (j.certificationStandard) $("inStandard").value = j.certificationStandard;
  if (j.certificateNumber) $("inNumber").value = j.certificateNumber;
  if (j.scope) $("inScope").value = j.scope;
  if (j.holderName) $("inHolderName").value = j.holderName;
  if (j.validUntil) $("inValidUntil").value = j.validUntil;
}

$("btnFile").addEventListener("click", () => $("fileInput").click());
$("fileInput").addEventListener("change", (ev) => {
  const f = ev.target.files[0];
  if (!f) return;
  const r = new FileReader();
  r.onload = () => {
    try {
      fillIsoForm(JSON.parse(r.result));
      $("fileStatus").textContent = "已從 " + f.name + " 匯入。";
    } catch {
      $("fileStatus").textContent = "JSON 解析失敗，請檢查檔案格式。";
    }
  };
  r.readAsText(f);
});

$("btnUploadVc").addEventListener("click", () => $("vcFileInput").click());
$("vcFileInput").addEventListener("change", (ev) => {
  const f = ev.target.files[0];
  ev.target.value = "";
  if (!f) return;
  const r = new FileReader();
  r.onload = () => {
    try {
      const vc = JSON.parse(r.result);
      if (!vc || typeof vc !== "object" || Array.isArray(vc)) throw new Error("不是 JSON 物件");
      $("vcOut").textContent = JSON.stringify(vc, null, 2);
      $("vcVerify").innerHTML = "";
      const hasProof = vc.proof !== undefined;
      setBadge(hasProof);
      $("vcCheck").innerHTML = '<span class="ok">已載入 ' + escHtml(f.name) + "（" + (hasProof ? "含 proof，可直接驗證" : "無 proof，只做結構驗證") + "）。</span>";
    } catch (e) {
      $("vcCheck").innerHTML = '<span style="color:#dc2626">VC 檔解析失敗：' + escHtml(e.message) + "</span>";
    }
  };
  r.readAsText(f);
});
