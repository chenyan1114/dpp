/* 共用核心（無 DOM）：編碼、JCS、驗證報告、Data Integrity 通用流程、VC 組裝與結構驗證。
   各 DID method 與 cryptosuite 由 did-key.js / did-ethr.js 註冊進 DID_METHODS / SUITES。 */
"use strict";

const DID_METHODS = {}; // "did:key:" 等前綴 → { name, generate(), parse(did), describe(info) }
const SUITES = {};      // cryptosuite 名稱 → { sigLen, fragment(did), note, sign(keys, hashData), verify(r, ctx) }

/* ---------- 編碼 ---------- */
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58btcEncode(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = "";
  for (; n > 0n; n /= 58n) out = B58[Number(n % 58n)] + out;
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) out = "1" + out;
  return out;
}

function base58btcDecode(str) {
  let n = 0n;
  for (const ch of str) {
    const i = B58.indexOf(ch);
    if (i < 0) throw new Error("base58 非法字元: " + ch);
    n = n * 58n + BigInt(i);
  }
  const tail = [];
  for (; n > 0n; n >>= 8n) tail.unshift(Number(n & 0xffn));
  const zeros = str.match(/^1*/)[0].length;
  return Uint8Array.from([...new Array(zeros).fill(0), ...tail]);
}

function concatBytes(...arrs) {
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let p = 0;
  for (const a of arrs) { out.set(a, p); p += a.length; }
  return out;
}

async function sha256(data) {
  if (typeof data === "string") data = new TextEncoder().encode(data);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

/* ---------- JCS（RFC 8785）：字串與數字的序列化規則就是 JSON.stringify，只需自己排序物件鍵 ---------- */
function jcs(v) {
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  if (v !== null && typeof v === "object") {
    return "{" + Object.keys(v).sort().map((k) => jcs(k) + ":" + jcs(v[k])).join(",") + "}";
  }
  if (typeof v === "string" && !v.isWellFormed()) throw new Error("JCS 不允許孤立 surrogate");
  if (typeof v === "number" && !Number.isFinite(v)) throw new Error("JCS 不允許 NaN/Infinity");
  const s = JSON.stringify(v);
  if (s === undefined) throw new Error("JCS 不允許 undefined/function/symbol");
  return s;
}

/* ---------- 驗證報告：fails 才算失敗；warns 只提醒 ---------- */
function report() {
  const r = { fails: [], warns: [], passes: [], infos: [] };
  r.check = (ok, pass, fail) => { (ok ? r.passes : r.fails).push(ok ? pass : fail); return ok; };
  r.soft = (ok, pass, warn) => { (ok ? r.passes : r.warns).push(ok ? pass : warn); return ok; };
  return r;
}

const isPlainObject = (x) => x !== null && typeof x === "object" && !Array.isArray(x);
const isDateTime = (x) => typeof x === "string" && !isNaN(Date.parse(x));

function didMethodOf(did) {
  const prefix = Object.keys(DID_METHODS).find((p) => typeof did === "string" && did.startsWith(p));
  if (!prefix) throw new Error("不支援的 DID method（只支援 " + Object.keys(DID_METHODS).join("、") + "）");
  return DID_METHODS[prefix];
}

/* ---------- Data Integrity 通用流程（所有 cryptosuite 共用）---------- */
// hashData = SHA256(JCS(proof options)) ‖ SHA256(JCS(未簽名文件))：proof options 在前
async function diHashData(proofOptions, doc) {
  return concatBytes(await sha256(jcs(proofOptions)), await sha256(jcs(doc)));
}

async function createProof(unsignedVc, keys, created = new Date().toISOString()) {
  const suite = SUITES[keys.cryptosuite];
  if (!suite) throw new Error("缺少 issuer 私鑰材料，請重新生成 DID");
  if (!isDateTime(created)) throw new Error("created 非法時間");
  if (unsignedVc.proof !== undefined) throw new Error("文件已含 proof，請重新生成未簽名的 VC 再簽");
  // ① 先組 proof options（此時還沒有 proofValue）
  const proofOptions = {
    type: "DataIntegrityProof",
    cryptosuite: keys.cryptosuite,
    created,
    verificationMethod: keys.verificationMethod ?? keys.did + "#" + suite.fragment(keys.did), // 委派金鑰會自帶 #delegate-N
    proofPurpose: "assertionMethod",
    "@context": unsignedVc["@context"],
  };
  // ② 對 proof options 與文件雜湊 → ③ 簽名 → ④ proofValue 掛回 proof
  const sig = await suite.sign(keys, await diHashData(proofOptions, unsignedVc));
  return { ...proofOptions, proofValue: "z" + base58btcEncode(sig) };
}

async function verifyProof(signedVc, ctx = {}) {
  const r = report();
  const proof = signedVc.proof;
  if (!isPlainObject(proof)) {
    r.fails.push("缺少 proof 物件（本 demo 只支援單一 proof）");
    return r;
  }
  const suite = SUITES[proof.cryptosuite];
  r.check(proof.type === "DataIntegrityProof", "proof.type 正確", 'proof.type 需為 "DataIntegrityProof"');
  if (!r.check(!!suite, `cryptosuite 為 ${proof.cryptosuite}${suite?.note ?? ""}`,
    `不支援的 cryptosuite：${proof.cryptosuite}（支援 ${Object.keys(SUITES).join("、")}）`)) return r;
  r.soft(proof.proofPurpose === "assertionMethod", "proofPurpose 為 assertionMethod",
    "proofPurpose 不是 assertionMethod（本 demo 預期 assertionMethod）");
  r.check(isDateTime(proof.created), "proof.created 為合法時間", "proof.created 非法時間");

  let sig = null;
  if (r.check(typeof proof.proofValue === "string" && proof.proofValue.startsWith("z"),
    "proofValue 為 z 開頭的 multibase base58btc", "proofValue 需為 z 開頭的 multibase base58btc")) {
    try {
      sig = base58btcDecode(proof.proofValue.slice(1));
      r.check(sig.length === suite.sigLen, `proofValue 解碼為 ${suite.sigLen}-byte 簽名`,
        `簽名長度應為 ${suite.sigLen} bytes，實際 ${sig.length}`);
    } catch (e) { r.fails.push("proofValue 解碼失敗：" + e.message); }
  }

  // verificationMethod = <DID>#<fragment>；fragment 合不合法由各 suite 的 verify 判斷
  const vm = proof.verificationMethod;
  let did = null, didInfo = null, fragment = null;
  if (r.check(typeof vm === "string" && vm.includes("#"), "verificationMethod 為 DID#fragment 形式",
    "verificationMethod 需為 DID 加 #fragment 形式")) {
    did = vm.slice(0, vm.indexOf("#"));
    fragment = vm.slice(vm.indexOf("#") + 1);
    try {
      didInfo = didMethodOf(did).parse(did);
      r.passes.push("verificationMethod 的 DID 解析成功");
    } catch (e) { r.fails.push("verificationMethod DID 非法：" + e.message); }
    r.check(did === signedVc.issuer, "verificationMethod 對應 VC issuer", "verificationMethod 的 DID 與 VC issuer 不一致");
  }
  if (r.fails.length) return r;

  // 轉換：拔掉 proofValue 得 proof options、拔掉 proof 得原文件，@context 以 proof 內副本為準
  const { proofValue, ...proofOptions } = proof;
  const { proof: _, ...unsecured } = signedVc;
  if (proofOptions["@context"] !== undefined) {
    const pc = [].concat(proofOptions["@context"]), dc = [].concat(unsecured["@context"]);
    if (!r.check(pc.length <= dc.length && pc.every((v, i) => dc[i] === v), "@context 前綴一致",
      "文件 @context 與 proof 內 @context 副本前綴不一致")) return r;
    unsecured["@context"] = proofOptions["@context"];
  }
  await suite.verify(r, { hashData: await diHashData(proofOptions, unsecured), sig, did, didInfo, fragment, ...ctx });
  return r;
}

/* ---------- VC v2.0 組裝與結構驗證 ---------- */
function buildVc({ standard, number, scope, holderName, validUntil }, issuerDid, holderDid) {
  if (!issuerDid || !holderDid) throw new Error("請先生成 issuer + holder DID");
  if (!standard || !number || !scope || !validUntil) throw new Error("ISO 欄位不可空白");
  const subject = { id: holderDid, certificationStandard: standard, certificateNumber: number, scope };
  if (holderName) subject.name = holderName;
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: "urn:uuid:" + crypto.randomUUID(),
    type: ["VerifiableCredential", "IsoCertificationCredential"],
    issuer: issuerDid,
    validFrom: new Date().toISOString(),
    validUntil: /^\d{4}-\d{2}-\d{2}$/.test(validUntil) ? validUntil + "T00:00:00Z" : validUntil,
    credentialSubject: subject,
  };
}

function checkDid(r, did, label) {
  try {
    const m = didMethodOf(did);
    r.passes.push(`${label} ${m.describe(m.parse(did))}`);
    return true;
  } catch (e) {
    r.fails.push(`${label} DID 非法：` + e.message);
    return false;
  }
}

/* form（可省略）= 頁面目前的表單值與 DID，用來比對；不一致只算提醒 */
function verifyVc(vc, form) {
  const r = report();
  if (!isPlainObject(vc)) { r.fails.push("VC 不是一個 JSON 物件"); return r; }
  const has = (arr, v) => Array.isArray(arr) && arr.includes(v);
  r.check(has(vc["@context"], "https://www.w3.org/ns/credentials/v2"), "@context 含 W3C v2",
    "@context 需包含 https://www.w3.org/ns/credentials/v2");
  r.check(has(vc.type, "VerifiableCredential"), "type 含 VerifiableCredential", 'type 需包含 "VerifiableCredential"');
  r.soft(has(vc.type, "IsoCertificationCredential"), "type 含 IsoCertificationCredential",
    '建議 type 加上 "IsoCertificationCredential"');
  const id = String(vc.id || "");
  if (/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) r.passes.push("id 為合法 urn:uuid");
  else if (id.startsWith("urn:uuid:")) r.warns.push("id 有 urn:uuid: 前綴但 UUID 格式不標準");
  else r.fails.push("id 需為 urn:uuid:<uuid> 格式");

  const subj = vc.credentialSubject || {};
  const issuerOk = checkDid(r, vc.issuer, "issuer");
  const holderOk = checkDid(r, subj.id, "credentialSubject.id");
  if (issuerOk && holderOk) {
    r.soft(vc.issuer !== subj.id, "issuer 與 holder 為不同 DID（非自簽）", "issuer 與 holder 相同（自簽憑證，demo 正常應為不同）");
  }
  for (const k of ["certificationStandard", "certificateNumber", "scope"]) {
    r.check(!!String(subj[k] ?? "").trim(), "claim 有 " + k, "缺 claim: " + k);
  }
  const from = Date.parse(vc.validFrom), until = Date.parse(vc.validUntil);
  r.check(!isNaN(from), "validFrom 為合法時間", "validFrom 非法或缺失（v2 必備）");
  r.check(!isNaN(until), "validUntil 為合法時間", "validUntil 非法或缺失");
  if (!isNaN(from) && !isNaN(until)) r.check(until > from, "validUntil 晚於 validFrom", "validUntil 應晚於 validFrom");

  if (form) {
    for (const [k, f] of [["certificationStandard", "standard"], ["certificateNumber", "number"], ["scope", "scope"]]) {
      r.soft(String(subj[k] ?? "") === String(form[f] ?? ""), `VC 的 ${k} 與表單一致`,
        `VC 的 ${k} 與目前表單不同（生成後改了表單？以 VC 內容為準）`);
    }
    if (form.validUntil) {
      r.soft(String(vc.validUntil || "").startsWith(form.validUntil.slice(0, 10)), "validUntil 日期與表單一致",
        "validUntil 與目前表單日期不同");
    }
    if (form.issuerDid && vc.issuer !== form.issuerDid) r.warns.push("issuer 與頁面上目前的 DID 不同（生成 VC 後重按了生成？）");
    if (form.holderDid && subj.id !== form.holderDid) r.warns.push("holder 與頁面上目前的 DID 不同（生成 VC 後重按了生成？）");
  }
  r.infos.push("proof" in vc ? "含 proof：按驗證會加做密碼學驗證"
    : "無 proof（unsigned）：以上只驗結構＋DID 解碼，無法做發證者密碼學驗證");
  return r;
}
