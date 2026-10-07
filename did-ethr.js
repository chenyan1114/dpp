/* did:ethr（Sepolia）＋ secp256k1 可回推簽名。
   secp256k1／keccak256／EIP-55 用 ethers.js v6（index.html 以 CDN 載入）；
   DID 解析用官方 ethr-did-resolver（讀 ERC-1056 registry 的鏈上事件組出 DID 文件，含委派金鑰、撤銷、owner 轉移）。
   本檔只做唯讀查詢，不送交易、不花 gas。 */
"use strict";

const ETHR = {
  network: "sepolia",
  chainId: 11155111,
  registry: "0x03d5003bf0e79C5F5223588F347ebA39AfbC3818", // ERC-1056 EthereumDIDRegistry（ethr-did-resolver 官方設定）
  cryptosuite: "ecdsa-secp256k1-recovery-jcs-demo",      // 教學用自訂名稱，非 W3C 標準套件
  // 需能讀「舊」事件的 RPC：publicnode 只保留約 1 萬個區塊的 log，委派金鑰一舊就解析不到
  defaultRpc: "https://sepolia.gateway.tenderly.co",
  // 版本須與 package.json 的 devDependencies 一致（test.js 會檢查）
  resolverModules: [
    "https://cdn.jsdelivr.net/npm/did-resolver@5.0.1/+esm",
    "https://cdn.jsdelivr.net/npm/ethr-did-resolver@14.1.4/+esm",
  ],
  importResolver: () => Promise.all(ETHR.resolverModules.map((u) => import(u))), // test.js 會換成 npm 版
};

function requireEthers() {
  if (typeof ethers === "undefined") throw new Error("ethers.js 未載入（did:ethr 需要網路載入 CDN）");
  return ethers;
}

/* ---------- DID 解析 ---------- */
const ethrResolvers = new Map(); // rpcUrl → Resolver

async function resolveDidEthr(did, rpcUrl = ETHR.defaultRpc) {
  if (!ethrResolvers.has(rpcUrl)) {
    const [{ Resolver }, { getResolver }] = await ETHR.importResolver();
    const networks = [{ name: ETHR.network, chainId: ETHR.chainId, rpcUrl, registry: ETHR.registry }];
    ethrResolvers.set(rpcUrl, new Resolver(getResolver({ networks })));
  }
  return ethrResolvers.get(rpcUrl).resolve(did);
}

/* 鏈上沒有任何變更時的預設 DID 文件：唯一的金鑰是 #controller = 地址本身 */
function defaultEthrDoc(did, address) {
  const vm = {
    id: did + "#controller",
    type: "EcdsaSecp256k1RecoveryMethod2020",
    controller: did,
    blockchainAccountId: `eip155:${ETHR.chainId}:${address}`,
  };
  return { id: did, verificationMethod: [vm], authentication: [vm.id], assertionMethod: [vm.id] };
}

const fragmentOf = (id) => String(id).slice(String(id).indexOf("#") + 1);

/* verificationMethod 條目 → 以太坊地址（resolver 用 blockchainAccountId；以屬性加入的金鑰用 publicKeyHex） */
function methodAddress(m) {
  const e = requireEthers();
  if (m.blockchainAccountId) return e.getAddress(m.blockchainAccountId.split(":").pop());
  if (m.publicKeyHex) return e.computeAddress("0x" + m.publicKeyHex);
  throw new Error(`不支援的金鑰表示法（${m.type}），本 demo 只認 blockchainAccountId／publicKeyHex`);
}

DID_METHODS["did:ethr:"] = {
  name: "did:ethr（Sepolia，secp256k1）",
  hint: "格式：did:ethr:sepolia:0x<以太坊地址>，地址 = keccak256(secp256k1 公鑰) 末 20 bytes。任何地址天生就是 did:ethr，" +
    "不需上鏈交易；鏈上 ERC-1056 registry 只在要改 DID 文件（換 owner、加委派、撤銷）時才寫入。",

  async generate() {
    const e = requireEthers();
    const signingKey = new e.SigningKey(e.randomBytes(32));
    return { did: `did:ethr:${ETHR.network}:${e.computeAddress(signingKey)}`, cryptosuite: ETHR.cryptosuite, signingKey };
  },

  /* did:ethr:<network>:0x<address>；只接受 Sepolia + 地址形式 */
  parse(did) {
    const m = /^did:ethr:(?:([^:]+):)?(0x[0-9a-fA-F]+)$/.exec(did);
    if (!m) throw new Error("格式應為 did:ethr:sepolia:0x<地址>");
    const network = m[1] ?? "mainnet";
    if (network !== ETHR.network && network.toLowerCase() !== "0x" + ETHR.chainId.toString(16)) {
      throw new Error(`網路是 ${network}，本 demo 只支援 Sepolia（sepolia 或 0xaa36a7）`);
    }
    if (m[2].length === 68) throw new Error("公鑰形式的 did:ethr 本 demo 未支援，請用地址形式");
    if (m[2].length !== 42) throw new Error("識別碼不是 20-byte 以太坊地址");
    try {
      return { address: requireEthers().getAddress(m[2]) }; // 大小寫混用時會檢查 EIP-55 校驗碼
    } catch (e) {
      throw new Error(e.code === "INVALID_ARGUMENT" ? "地址 EIP-55 校驗碼錯誤（大小寫被改過）" : e.message);
    }
  },

  describe: ({ address }) => `did:ethr 解析成功（Sepolia，地址 ${address}）`,

  resolve(did, { rpcUrl } = {}) {
    this.parse(did);
    return resolveDidEthr(did, rpcUrl);
  },
};

/* 驗證用：解析 DID 文件。連不上 → 退回預設文件並提醒；停用或其他錯誤 → 失敗（回傳 null） */
async function resolveForVerify(r, did, didInfo, rpcUrl) {
  let res;
  try {
    res = await resolveDidEthr(did, rpcUrl || ETHR.defaultRpc);
  } catch (err) {
    res = { didResolutionMetadata: { error: "internalError", message: err.message } };
  }
  const { error, message } = res.didResolutionMetadata ?? {};
  if (error === "internalError") {
    r.warns.push(`無法從 Sepolia 解析 DID 文件（${message}），改用離線預設文件：只有 #controller = DID 地址本身`);
    return defaultEthrDoc(did, didInfo.address);
  }
  if (error) {
    r.fails.push(`DID 解析失敗：${error}${message ? "（" + message + "）" : ""}`);
    return null;
  }
  const meta = res.didDocumentMetadata ?? {};
  if (meta.deactivated) {
    r.fails.push("此 DID 已在鏈上停用（owner 設為 0x0），不可再用於驗證");
    return null;
  }
  r.passes.push(meta.versionId
    ? `已從 Sepolia 解析 DID 文件（最後一次鏈上變更：區塊 ${meta.versionId}，${meta.updated}）`
    : "已從 Sepolia 解析 DID 文件（從未在鏈上變更，即預設文件）");
  return res.didDocument;
}

SUITES[ETHR.cryptosuite] = {
  sigLen: 65, // r ‖ s ‖ recId(0/1)
  fragment: () => "controller", // 預設用 #controller 簽；委派金鑰由 keys.verificationMethod 指定 #delegate-N
  note: "（教學用，非 W3C 標準）",

  // 與 eddsa-jcs-2022 相同的 hashData；ECDSA 簽它的 SHA-256 摘要（同 JOSE ES256K），RFC 6979 決定性 k、low-S
  async sign(keys, hashData) {
    const s = keys.signingKey.sign(await sha256(hashData));
    return concatBytes(ethers.getBytes(s.r), ethers.getBytes(s.s), [s.yParity]);
  },

  async verify(r, { hashData, sig, did, didInfo, fragment, rpcUrl }) {
    const e = requireEthers();
    if (!r.check(e.toBigInt(sig.slice(32, 64)) <= e.N / 2n, "s 為 low-S", "s 不是 low-S（以太坊拒收可延展簽名）")) return;
    let recovered;
    try {
      recovered = e.recoverAddress(await sha256(hashData), e.hexlify(sig));
      r.passes.push("從簽名回推出簽名者地址 " + recovered);
    } catch (err) {
      r.fails.push("簽名無法回推公鑰：" + (err.shortMessage || err.message));
      return;
    }

    const doc = await resolveForVerify(r, did, didInfo, rpcUrl);
    if (!doc) return;
    // 在 DID 文件裡找 verificationMethod 指到的那把鑰匙，且它必須被授權做 assertionMethod
    const m = (doc.verificationMethod ?? []).find((v) => fragmentOf(v.id) === fragment);
    if (!r.check(!!m, `DID 文件中有 #${fragment}（${m?.type}）`,
      `DID 文件裡沒有 #${fragment}（金鑰不存在、已撤銷或已過期）`)) return;
    r.check((doc.assertionMethod ?? []).some((a) => fragmentOf(a.id ?? a) === fragment),
      `#${fragment} 列在 assertionMethod（可用來簽發憑證）`, `#${fragment} 未列在 assertionMethod，不可用來簽發憑證`);
    let expected;
    try {
      expected = methodAddress(m);
    } catch (err) {
      r.fails.push(err.message);
      return;
    }
    if (fragment === "controller" && expected !== didInfo.address) {
      r.warns.push(`此 DID 的 owner 已在鏈上轉移至 ${expected}，以新 owner 為準`);
    }
    r.check(recovered === expected,
      `secp256k1 簽名驗證通過：回推地址 = #${fragment} 的地址（未竄改 ✓ 確為 issuer 授權的金鑰所簽 ✓）`,
      `簽名驗證失敗：回推地址 ${recovered} ≠ #${fragment} 的地址 ${expected}（文件曾被竄改，或非 issuer 授權的金鑰所簽）`);
  },
};
