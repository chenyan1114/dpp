/* UI 接線：只處理 DOM，邏輯都在 vc.js / did-key.js / did-ethr.js。 */
"use strict";

const $ = (id) => document.getElementById(id);
let issuerKeys = null, holderKeys = null; // 私鑰只留在記憶體，重整頁面即銷毀
let wallet = null; // 已連接的 MetaMask：{ provider, signer, address, did }

function on(id, handler) {
  $(id).addEventListener("click", async () => {
    $(id).disabled = true;
    try { await handler(); } finally { $(id).disabled = false; }
  });
}

function showStatus(id, cls, text) {
  $(id).className = cls;
  $(id).textContent = text;
}

/* 選檔後讀 JSON（同一個檔案可重複選） */
function onJsonFile(inputId, onLoad, onError) {
  $(inputId).addEventListener("change", async (ev) => {
    const f = ev.target.files[0];
    ev.target.value = "";
    if (!f) return;
    try { onLoad(JSON.parse(await f.text()), f.name); } catch (e) { onError(e); }
  });
}

const selectedMethod = () => DID_METHODS[document.querySelector('input[name="didMethod"]:checked').value];

function readForm() {
  const v = (id) => $(id).value.trim();
  return { standard: v("inStandard"), number: v("inNumber"), scope: v("inScope"), holderName: v("inHolderName"), validUntil: v("inValidUntil") };
}

function fillIsoForm(j) {
  const map = { certificationStandard: "inStandard", certificateNumber: "inNumber", scope: "inScope", holderName: "inHolderName", validUntil: "inValidUntil" };
  for (const [k, id] of Object.entries(map)) if (j[k]) $(id).value = j[k];
}

function renderKeys(status) {
  $("issuerDid").textContent = issuerKeys?.did ?? "尚未生成";
  $("holderDid").textContent = holderKeys?.did ?? "尚未生成";
  $("keyMethod").textContent = status;
}

function showVc(vc) {
  $("vcOut").textContent = JSON.stringify(vc, null, 2);
  $("vcVerify").replaceChildren();
  const suite = vc.proof === undefined ? null : String(vc.proof.cryptosuite || "unknown suite");
  $("signBadge").textContent = suite ? "SIGNED · " + suite : "UNSIGNED";
  $("signBadge").classList.toggle("signed", !!suite);
}

function renderReport(r) {
  const box = $("vcVerify");
  box.replaceChildren();
  const add = (cls, text, tag = "div") => {
    const el = document.createElement(tag);
    el.className = cls;
    el.textContent = text;
    box.append(el);
  };
  add(r.fails.length ? "err summary" : "ok summary", r.fails.length
    ? `驗證失敗：${r.fails.length} 項錯誤`
    : `驗證通過：${r.passes.length} 項檢查全過${r.warns.length ? `（另 ${r.warns.length} 項提醒）` : ""}`, "p");
  for (const [cls, sym, list] of [["err", "✗", r.fails], ["warn", "⚠", r.warns], ["pass", "✓", r.passes], ["info", "ℹ", r.infos]]) {
    for (const t of list) add(cls, sym + " " + t);
  }
}

/* ---------- 1. ISO 證書輸入 ---------- */
$("btnFile").addEventListener("click", () => $("fileInput").click());
onJsonFile("fileInput",
  (j, name) => { fillIsoForm(j); $("fileStatus").textContent = "已匯入 " + name + "。"; },
  () => { $("fileStatus").textContent = "JSON 解析失敗。"; });

/* ---------- 2. DID ---------- */
document.querySelectorAll('input[name="didMethod"]').forEach((el) =>
  el.addEventListener("change", () => { $("methodHint").textContent = selectedMethod().hint; }));
$("methodHint").textContent = selectedMethod().hint;

on("btnGen", async () => {
  $("keyMethod").textContent = "生成中…";
  try {
    const m = selectedMethod();
    issuerKeys = await m.generate();
    holderKeys = await m.generate();
    renderKeys(`✓ 已生成 ${m.name}，私鑰只在頁面記憶體。`);
    $("inResolveDid").value = issuerKeys.did;
  } catch (e) {
    $("keyMethod").textContent = "生成失敗：" + e.message;
  }
});

on("btnResolve", async () => {
  const out = $("didDocOut");
  out.hidden = false;
  out.textContent = "解析中…";
  try {
    const did = $("inResolveDid").value.trim();
    const res = await didMethodOf(did).resolve(did, { rpcUrl: $("inRpc").value.trim() || undefined });
    out.textContent = JSON.stringify(res, null, 2);
  } catch (e) {
    out.textContent = "解析失敗：" + e.message;
  }
});

on("btnClearKeys", () => {
  issuerKeys = holderKeys = null;
  renderKeys("私鑰只存在頁面記憶體，重新整理就消失。");
});

/* ---------- 2b. 鏈上授權（MetaMask）---------- */
function showWallet(cls, text, txHash) {
  showStatus("walletStatus", cls, text);
  if (!txHash) return;
  const a = document.createElement("a");
  a.href = `${ETHR.explorer}/tx/${txHash}`;
  a.target = "_blank";
  a.rel = "noopener";
  a.textContent = " Etherscan ↗";
  $("walletStatus").append(a);
}

const walletIssuer = () => (wallet && issuerKeys?.did === wallet.did ? issuerKeys : null);

on("btnWallet", async () => {
  showWallet("", "請在 MetaMask 確認連接…");
  try {
    wallet = await connectEthrWallet();
    const ethrM = DID_METHODS["did:ethr:"];
    const signer = await ethrM.generate(); // 頁面產生的簽名金鑰，之後由你的 DID 授權
    issuerKeys = { did: wallet.did, cryptosuite: signer.cryptosuite, signingKey: signer.signingKey, address: signer.address, viaWallet: true };
    if (!holderKeys?.did.startsWith("did:ethr:")) holderKeys = await ethrM.generate();
    document.querySelector('input[value="did:ethr:"]').checked = true;
    $("methodHint").textContent = ethrM.hint;
    $("inResolveDid").value = wallet.did;
    renderKeys(`issuer = 你的 MetaMask 帳戶；簽名金鑰 ${signer.address}（未授權）`);
    showWallet("ok", `✓ 已連接 ${wallet.address}。下一步：🔗 授權。`);
  } catch (e) {
    wallet = null;
    showWallet("err", "連接失敗：" + walletErrorMessage(e));
  }
});

on("btnDelegate", async () => {
  const keys = walletIssuer();
  if (!keys) return showWallet("err", "請先 🦊 連接 MetaMask。");
  const validity = Number($("inValidity").value);
  showWallet("", "請在 MetaMask 確認交易，上鏈約需 10–30 秒…");
  try {
    const receipt = await addEthrDelegate(wallet, keys.address, validity);
    showWallet("", "已上鏈，更新 DID 文件中…", receipt.hash);
    const fragment = await waitForDelegate(wallet.did, keys.address, $("inRpc").value.trim(), true);
    keys.verificationMethod = `${wallet.did}#${fragment}`;
    const until = new Date(Date.now() + validity * 1000).toLocaleString();
    showWallet("ok", `✓ 已授權為 #${fragment}，約到 ${until} 有效。可以到第 3 卡簽名了。`, receipt.hash);
    renderKeys(`issuer = 你的 MetaMask 帳戶；簽名金鑰 ${keys.address} = #${fragment}（已授權）`);
  } catch (e) {
    showWallet("err", "授權失敗：" + walletErrorMessage(e));
  }
});

on("btnRevoke", async () => {
  const keys = walletIssuer();
  if (!keys) return showWallet("err", "請先 🦊 連接 MetaMask。");
  showWallet("", "請在 MetaMask 確認交易…");
  try {
    const receipt = await revokeEthrDelegate(wallet, keys.address);
    showWallet("", "已上鏈，更新 DID 文件中…", receipt.hash);
    await waitForDelegate(wallet.did, keys.address, $("inRpc").value.trim(), false);
    const old = keys.verificationMethod;
    keys.verificationMethod = undefined;
    showWallet("ok", `✓ 已撤銷${old ? " #" + old.split("#")[1] : ""}，它簽過的 VC 現在驗不過。`, receipt.hash);
    renderKeys(`issuer = 你的 MetaMask 帳戶；簽名金鑰 ${keys.address}（已撤銷）`);
  } catch (e) {
    showWallet("err", "撤銷失敗：" + walletErrorMessage(e));
  }
});

// 在 MetaMask 切換帳戶或網路後，舊的連線狀態就不能用了
globalThis.ethereum?.on?.("accountsChanged", () => { if (wallet) { wallet = null; showWallet("err", "MetaMask 帳戶已切換，請重新連接。"); } });
globalThis.ethereum?.on?.("chainChanged", () => { if (wallet) { wallet = null; showWallet("err", "MetaMask 網路已切換，請重新連接。"); } });

/* ---------- 3. VC 生成／簽名／驗證 ---------- */
on("btnIssue", () => {
  try {
    const vc = buildVc(readForm(), issuerKeys?.did, holderKeys?.did);
    showVc(vc);
    const { fails } = verifyVc(vc);
    showStatus("vcCheck", fails.length ? "err" : "ok",
      fails.length ? "✗ " + fails.join("；") : "✓ 已生成（未簽名）");
  } catch (e) {
    $("vcOut").textContent = "生成失敗：" + e.message;
    showStatus("vcCheck", "", "");
  }
});

on("btnSign", async () => {
  try {
    const vc = JSON.parse($("vcOut").textContent);
    if (!issuerKeys || issuerKeys.did !== vc.issuer) {
      throw new Error("這份 VC 的 issuer 不是頁面上目前的 DID，請重新生成 VC。");
    }
    if (issuerKeys.viaWallet && !issuerKeys.verificationMethod) {
      throw new Error("請先在第 2 卡 🔗 授權簽名金鑰。");
    }
    const proof = await createProof(vc, issuerKeys);
    showVc({ ...vc, proof });
    showStatus("vcCheck", "ok", `✓ 已簽名（${proof.cryptosuite}）。`);
  } catch (e) {
    showStatus("vcCheck", "err", "簽名失敗：" + e.message);
  }
});

on("btnVerify", async () => {
  let vc;
  try {
    vc = JSON.parse($("vcOut").textContent);
  } catch {
    $("vcVerify").replaceChildren();
    showStatus("vcCheck", "err", "請先生成或上傳一份 VC。");
    return;
  }
  $("vcVerify").textContent = "驗證中…";
  const r = verifyVc(vc, { ...readForm(), issuerDid: issuerKeys?.did, holderDid: holderKeys?.did });
  if (isPlainObject(vc) && vc.proof !== undefined) {
    try {
      const pr = await verifyProof(vc, { rpcUrl: $("inRpc").value.trim() || undefined });
      for (const k of ["passes", "warns", "fails"]) r[k].push(...pr[k].map((t) => "[簽名] " + t));
    } catch (e) {
      r.fails.push("[簽名] 驗證過程出錯：" + e.message);
    }
  }
  renderReport(r);
});

on("btnCopy", async () => {
  try {
    await navigator.clipboard.writeText($("vcOut").textContent);
    showStatus("vcCheck", "ok", "已複製。");
  } catch {
    showStatus("vcCheck", "err", "複製失敗：瀏覽器不允許存取剪貼簿。");
  }
});

on("btnDownload", () => {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([$("vcOut").textContent], { type: "application/json" }));
  a.download = "vc.json";
  a.click();
  URL.revokeObjectURL(a.href);
});

$("btnUploadVc").addEventListener("click", () => $("vcFileInput").click());
onJsonFile("vcFileInput",
  (vc, name) => {
    if (!isPlainObject(vc)) throw new Error("不是 JSON 物件");
    showVc(vc);
    showStatus("vcCheck", "ok", `已載入 ${name}${vc.proof !== undefined ? "" : "（未簽名）"}。`);
  },
  (e) => showStatus("vcCheck", "err", "VC 檔解析失敗：" + e.message));
