/* 執行：npm install（一次）→ node test.js。需 Node 20+ 與網路：
   ethers 從 index.html 同一個 CDN 網址載入；DID 解析器用 npm 裝的同版本（Node 無法在 vm 內 import https 網址）。
   載入與頁面相同的 vc.js / did-key.js / did-ethr.js（無 DOM），驗證官方向量、新舊格式相容、DID 解析與竄改偵測。 */
"use strict";
const fs = require("fs");
const vm = require("vm");
const path = require("path");
const nodeCrypto = require("crypto");

const read = (f) => fs.readFileSync(path.join(__dirname, f), "utf8");
let passed = 0, failed = 0;
function t(name, ok, detail = "") {
  ok ? passed++ : failed++;
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${!ok && detail ? "\n     " + detail : ""}`);
}

async function loadScripts() {
  const html = read("index.html");
  const [, url, sri] = /<script src="(https:[^"]+ethers[^"]+)"\s+integrity="([^"]+)"/.exec(html);
  const src = Buffer.from(await (await fetch(url)).arrayBuffer());
  t("ethers CDN 檔案符合 index.html 的 SRI", "sha512-" + nodeCrypto.createHash("sha512").update(src).digest("base64") === sri);
  const ctx = vm.createContext({ crypto: globalThis.crypto, TextEncoder, TextDecoder, fetch, AbortController,
    setTimeout, clearTimeout, URL, Headers, Request, Response, console });
  ctx.globalThis = ctx.window = ctx.self = ctx;
  vm.runInContext(src.toString("utf8"), ctx, { filename: "ethers.umd.min.js" });
  for (const f of ["vc.js", "did-key.js", "did-ethr.js"]) vm.runInContext(read(f), ctx, { filename: f });
  // 頂層 const 不會掛在 ctx 上，用一段腳本把要測的名稱取出來
  const L = vm.runInContext("({ jcs, sha256, base58btcDecode, createProof, verifyProof, verifyVc, buildVc, DID_METHODS, SUITES, ETHR, ethers })", ctx);

  // 頁面從 CDN import 解析器；測試改用 npm 裝的同版本，並確認版本號一致
  const npmVersions = L.ETHR.resolverModules.map((u) => {
    const [, name, ver] = /npm\/(.+)@([^/]+)\/\+esm$/.exec(u);
    return [name, ver, JSON.parse(read(`node_modules/${name}/package.json`)).version];
  });
  t("CDN 解析器版本 = npm 測試版本", npmVersions.every(([, a, b]) => a === b), JSON.stringify(npmVersions));
  L.ETHR.importResolver = async () => [require("did-resolver"), require("ethr-did-resolver")];
  return L;
}

/* 假解析器：固定回傳給定的 DID 文件，用來測「委派金鑰」等需要鏈上寫入才會出現的情境 */
function stubResolver(docFor) {
  return async () => [
    { Resolver: class { async resolve(did) { return docFor(did); } } },
    { getResolver: () => ({}) },
  ];
}

const hex = (b) => Buffer.from(b).toString("hex");
const clone = (x) => JSON.parse(JSON.stringify(x));
const failsOf = (r) => r.fails.join(" | ");

(async () => {
  const L = await loadScripts();
  const keyM = L.DID_METHODS["did:key:"], ethrM = L.DID_METHODS["did:ethr:"];

  /* ---------- W3C vc-di-eddsa 附錄 B.3（eddsa-jcs-2022）官方向量 ---------- */
  const w3cDoc = {
    "@context": ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"],
    id: "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
    type: ["VerifiableCredential", "AlumniCredential"],
    name: "Alumni Credential",
    description: "A minimum viable example of an Alumni Credential.",
    issuer: "https://vc.example/issuers/5678",
    validFrom: "2023-01-01T00:00:00Z",
    credentialSubject: { id: "did:example:abcdefgh", alumniOf: "The School of Examples" },
  };
  const w3cDid = "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";
  t("JCS(官方文件) 逐字等於官方正規字串", L.jcs(w3cDoc) ===
    '{"@context":["https://www.w3.org/ns/credentials/v2","https://www.w3.org/ns/credentials/examples/v2"],"credentialSubject":{"alumniOf":"The School of Examples","id":"did:example:abcdefgh"},"description":"A minimum viable example of an Alumni Credential.","id":"urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33","issuer":"https://vc.example/issuers/5678","name":"Alumni Credential","type":["VerifiableCredential","AlumniCredential"],"validFrom":"2023-01-01T00:00:00Z"}');
  t("SHA-256(文件) 等於官方 59b7cb62…", hex(await L.sha256(L.jcs(w3cDoc))) === "59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19");

  // secretKeyMultibase = z + base58(0x8026 + 32-byte seed)；包成 PKCS#8 給 WebCrypto 匯入
  const seed = L.base58btcDecode("3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq").slice(2);
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  const privateKey = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"]);
  const jwk = await crypto.subtle.exportKey("jwk", privateKey);
  t("官方私鑰推導的公鑰 = 官方 did:key", hex(Buffer.from(jwk.x, "base64url")) === hex(keyM.parse(w3cDid).pub));
  const w3cProof = await L.createProof(w3cDoc, { did: w3cDid, cryptosuite: "eddsa-jcs-2022", privateKey }, "2023-02-24T23:36:38Z");
  t("createProof 重現官方 proofValue", w3cProof.proofValue ===
    "z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX", w3cProof.proofValue);
  const w3cR = await L.verifyProof({ ...w3cDoc, proof: w3cProof });
  t("官方向量：簽名通過，但 issuer 是 URL 故報不一致（預期行為）",
    w3cR.passes.some((p) => p.startsWith("Ed25519 簽名驗證通過")) || w3cR.fails.length === 1 && /issuer 不一致/.test(w3cR.fails[0]), failsOf(w3cR));

  /* ---------- JCS 邊界 ---------- */
  const throws = (f) => { try { f(); return false; } catch { return true; } };
  t("JCS 拒絕孤立 surrogate／NaN／undefined", throws(() => L.jcs("\ud800")) && throws(() => L.jcs(NaN)) && throws(() => L.jcs({ a: undefined })));
  t("JCS 鍵以 UTF-16 排序、非 ASCII 原樣保留", L.jcs({ "é": 1, b: [true, null], a: "中\n" }) === '{"a":"中\\n","b":[true,null],"é":1}');

  /* ---------- 兩種 DID method：簽發、驗證、竄改 ---------- */
  const form = { standard: "ISO 9001:2015", number: "TW-2026-QA-0891", scope: "Design and manufacture of electronic components", holderName: "Acme", validUntil: "2029-09-16" };
  for (const m of [keyM, ethrM]) {
    const issuer = await m.generate(), holder = await m.generate();
    const vc = L.buildVc(form, issuer.did, holder.did);
    t(`[${issuer.cryptosuite}] 未簽名 VC 結構檢查無錯誤`, L.verifyVc(vc).fails.length === 0, failsOf(L.verifyVc(vc)));
    const signed = { ...vc, proof: await L.createProof(vc, issuer) };
    const r = await L.verifyProof(signed, { rpcUrl: L.ETHR.defaultRpc });
    t(`[${issuer.cryptosuite}] 現簽現驗通過`, r.fails.length === 0, failsOf(r));
    if (r.warns.length) console.log("     提醒：" + r.warns.join(" | "));

    const tampered = [
      ["改 claim", (v) => { v.credentialSubject.scope += "!"; }],
      ["改 proof options 的 created", (v) => { v.proof.created = "2020-01-01T00:00:00Z"; }],
      ["加欄位", (v) => { v.extra = 1; }],
      ["刪 proof 內 @context", (v) => { delete v.proof["@context"]; }],
      ["換 issuer", (v) => { v.issuer = holder.did; v.proof.verificationMethod = holder.did + "#" + L.SUITES[issuer.cryptosuite].fragment(holder.did); }],
    ];
    for (const [name, mutate] of tampered) {
      const v = clone(signed);
      mutate(v);
      t(`[${issuer.cryptosuite}] 竄改「${name}」→ 驗證失敗`, (await L.verifyProof(v, { rpcUrl: L.ETHR.defaultRpc })).fails.length > 0);
    }
  }

  /* ---------- did:ethr 專屬 ---------- */
  const e = L.ethers;
  const issuer = await ethrM.generate();
  const vc = L.buildVc(form, issuer.did, (await ethrM.generate()).did);
  const signed = { ...vc, proof: await L.createProof(vc, issuer) };
  const offline = await L.verifyProof(signed, { rpcUrl: "https://invalid.example.invalid" });
  t("[ethr] RPC 連不上 → 降級離線驗證仍通過並提醒", offline.fails.length === 0 && offline.warns.some((w) => w.includes("無法從 Sepolia 解析")), failsOf(offline) + " / " + offline.warns.join(" | "));

  const raw = L.base58btcDecode(signed.proof.proofValue.slice(1));
  const highS = e.getBytes(e.concat([raw.slice(0, 32), e.toBeHex(e.N - e.toBigInt(raw.slice(32, 64)), 32), e.toBeHex(raw[64] ^ 1)]));
  const mal = clone(signed);
  mal.proof.proofValue = "z" + e.encodeBase58(highS);
  t("[ethr] high-S 可延展簽名被拒", (await L.verifyProof(mal, {})).fails.some((f) => f.includes("low-S")));

  const addr = issuer.did.split(":")[3];
  const i = [...addr.slice(2)].findIndex((c) => /[a-f]/i.test(c)) + 2;
  const flipped = addr.slice(0, i) + (addr[i] === addr[i].toUpperCase() ? addr[i].toLowerCase() : addr[i].toUpperCase()) + addr.slice(i + 1);
  t("[ethr] EIP-55 校驗碼被改 → 拒絕", throws(() => ethrM.parse("did:ethr:sepolia:" + flipped)));
  t("[ethr] 全小寫地址可接受", ethrM.parse("did:ethr:sepolia:" + addr.toLowerCase()).address === addr);
  t("[ethr] mainnet DID 被拒", throws(() => ethrM.parse("did:ethr:" + addr)));
  t("[ethr] chainId 形式 0xaa36a7 可接受", ethrM.parse("did:ethr:0xaa36a7:" + addr).address === addr);

  /* ---------- did:ethr DID 解析：Sepolia 上的真實 DID（公開鏈上資料，經 ethr-did-resolver 解析） ---------- */
  const RPC = L.ETHR.defaultRpc;
  const real = {
    delegated: "did:ethr:sepolia:0xdA1B435Cdc39C05901B02cB0f793e924b2D67750",   // 有 #delegate-1、#delegate-2
    deactivated: "did:ethr:sepolia:0xd773C0E52f7734e773f1F847EDBBef0127301C3C", // owner 已設為 0x0
    ownerMoved: "did:ethr:sepolia:0x39d27624a7a517F977ccD495E41d2472Ef480847",  // owner 已轉移
  };
  const res = await ethrM.resolve(real.delegated, { rpcUrl: RPC });
  const am = (res.didDocument?.assertionMethod ?? []).map((a) => String(a.id ?? a).split("#")[1]);
  t("[解析] 真實 DID 的委派金鑰出現在 assertionMethod", am.includes("delegate-1") && am.includes("delegate-2"),
    JSON.stringify(res.didResolutionMetadata) + " " + am);

  // 用隨機金鑰冒充這些 DID 簽 VC：驗證都必須失敗，且失敗原因要對
  const forge = async (did, fragment) => {
    const k = await ethrM.generate();
    const v = L.buildVc(form, did, issuer.did);
    const signedV = { ...v, proof: await L.createProof(v, { ...k, did, verificationMethod: `${did}#${fragment}` }) };
    return L.verifyProof(signedV, { rpcUrl: RPC });
  };
  let fr = await forge(real.delegated, "delegate-1");
  t("[解析] 冒用他人的 #delegate-1 → 地址不符而失敗", fr.fails.some((f) => f.includes("≠ #delegate-1")), failsOf(fr));
  fr = await forge(real.delegated, "delegate-9");
  t("[解析] 不存在的 #delegate-9 → 失敗", fr.fails.some((f) => f.includes("沒有 #delegate-9")), failsOf(fr));
  fr = await forge(real.deactivated, "controller");
  t("[解析] 已停用的 DID → 失敗", fr.fails.some((f) => f.includes("停用")), failsOf(fr));
  fr = await forge(real.ownerMoved, "controller");
  t("[解析] owner 已轉移：原地址的鑰匙不再有效，並提醒新 owner",
    fr.fails.some((f) => f.includes("≠ #controller")) && fr.warns.some((w) => w.includes("轉移")), failsOf(fr));

  // 委派金鑰「正向」流程需要先上鏈 addDelegate（第 2 步），這裡用假解析器模擬鏈上狀態
  const owner = await ethrM.generate(), delegate = await ethrM.generate();
  const delegateAddr = delegate.did.split(":")[3];
  const docWith = (withDelegate) => (did) => {
    const ctrl = { id: did + "#controller", type: "EcdsaSecp256k1RecoveryMethod2020", controller: did, blockchainAccountId: `eip155:11155111:${did.split(":")[3]}` };
    const del = { id: did + "#delegate-1", type: "EcdsaSecp256k1RecoveryMethod2020", controller: did, blockchainAccountId: `eip155:11155111:${delegateAddr}` };
    const vms = withDelegate ? [ctrl, del] : [ctrl];
    return { didDocument: { id: did, verificationMethod: vms, assertionMethod: vms.map((m) => m.id) }, didDocumentMetadata: { versionId: "1", updated: "stub" }, didResolutionMetadata: {} };
  };
  const vcD = L.buildVc(form, owner.did, issuer.did);
  const signedD = { ...vcD, proof: await L.createProof(vcD, { ...delegate, did: owner.did, verificationMethod: owner.did + "#delegate-1" }) };
  t("[委派] proof 的 verificationMethod 為 #delegate-1", signedD.proof.verificationMethod.endsWith("#delegate-1"));
  const realImport = L.ETHR.importResolver;
  L.ETHR.importResolver = stubResolver(docWith(true));
  fr = await L.verifyProof(signedD, { rpcUrl: "stub://with-delegate" });
  t("[委派] 鏈上已授權 → 委派金鑰簽的 VC 通過", fr.fails.length === 0, failsOf(fr));
  L.ETHR.importResolver = stubResolver(docWith(false));
  fr = await L.verifyProof(signedD, { rpcUrl: "stub://revoked" });
  t("[委派] 撤銷後 → 同一份 VC 失敗", fr.fails.some((f) => f.includes("沒有 #delegate-1")), failsOf(fr));
  L.ETHR.importResolver = realImport;

  /* ---------- did:key 解析 ---------- */
  const kd = (await keyM.generate()).did;
  const kres = await keyM.resolve(kd);
  t("[解析] did:key 文件由字串推導，含 Multikey 公鑰", kres.didDocument.verificationMethod[0].publicKeyMultibase === kd.slice(8));

  /* ---------- 重構前舊程式簽出的 VC 仍可驗證（格式相容） ---------- */
  for (const { kind, vc: old } of JSON.parse(read("test-fixtures.json"))) {
    const r = await L.verifyProof(old, { rpcUrl: L.ETHR.defaultRpc });
    t(`舊版 VC（${kind}）新程式驗證通過`, r.fails.length === 0, failsOf(r));
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exitCode = failed ? 1 : 0;
})().catch((err) => { console.error(err); process.exitCode = 1; });
