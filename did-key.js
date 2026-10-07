/* did:key（Ed25519）＋ eddsa-jcs-2022（W3C 標準）。金鑰與簽章全用瀏覽器內建 WebCrypto，離線可用。 */
"use strict";

const ED25519 = { name: "Ed25519" };

function didKeyFromPub(pub32) {
  return "did:key:z" + base58btcEncode(concatBytes([0xed, 0x01], pub32)); // multicodec 0xED01 = ed25519-pub
}

DID_METHODS["did:key:"] = {
  name: "did:key（Ed25519）",
  hint: "公鑰直接編在 DID 字串裡，不需任何註冊中心，離線可驗。",

  async generate() {
    let keypair;
    try {
      keypair = await crypto.subtle.generateKey(ED25519, false, ["sign", "verify"]);
    } catch {
      throw new Error("此瀏覽器的 WebCrypto 不支援 Ed25519，請更新瀏覽器");
    }
    const pub = new Uint8Array(await crypto.subtle.exportKey("raw", keypair.publicKey));
    return { did: didKeyFromPub(pub), cryptosuite: "eddsa-jcs-2022", privateKey: keypair.privateKey };
  },

  parse(did) {
    if (!did.startsWith("did:key:z")) throw new Error("不是 did:key:z 開頭");
    const raw = base58btcDecode(did.slice("did:key:z".length));
    if (raw.length !== 34) throw new Error("解碼後長度應為 34 bytes，實際 " + raw.length);
    if (raw[0] !== 0xed || raw[1] !== 0x01) throw new Error("multicodec 前綴不是 0xED01（非 Ed25519）");
    return { pub: raw.slice(2) };
  },

  describe: () => "did:key 解碼成功（0xED01 前綴，32-byte Ed25519 公鑰）",

  /* did:key 的 DID 文件由 DID 字串本身推導，不需查任何註冊中心 */
  async resolve(did) {
    this.parse(did);
    const vmId = did + "#" + did.slice("did:key:".length);
    return {
      didDocument: {
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
        id: did,
        verificationMethod: [{ id: vmId, type: "Multikey", controller: did, publicKeyMultibase: did.slice("did:key:".length) }],
        authentication: [vmId],
        assertionMethod: [vmId],
      },
      didDocumentMetadata: {},
      didResolutionMetadata: { note: "由 DID 字串離線推導，無註冊中心、無法更新或撤銷" },
    };
  },
};

SUITES["eddsa-jcs-2022"] = {
  sigLen: 64,
  fragment: (did) => did.slice("did:key:".length), // verificationMethod = did#<同一把公鑰的指紋>
  note: "",

  async sign(keys, hashData) {
    return new Uint8Array(await crypto.subtle.sign(ED25519, keys.privateKey, hashData));
  },

  async verify(r, { hashData, sig, did, didInfo, fragment }) {
    const want = this.fragment(did);
    r.soft(fragment === want, `verificationMethod fragment 正確（#${want.slice(0, 12)}…）`,
      "verificationMethod fragment 與 did:key 指紋不一致（互通性警告）");
    let ok = false;
    try {
      const pubKey = await crypto.subtle.importKey("raw", didInfo.pub, ED25519, false, ["verify"]);
      ok = await crypto.subtle.verify(ED25519, pubKey, sig, hashData);
    } catch (e) {
      r.fails.push("公鑰無法匯入或驗證出錯：" + e.message);
      return;
    }
    r.check(ok, "Ed25519 簽名驗證通過（未竄改 ✓ 確為 issuer 私鑰所簽 ✓）",
      "簽名驗證失敗：文件曾被竄改，或非 issuer 私鑰所簽");
  },
};
