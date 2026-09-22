先實作一個簡單生成VC的小功能。

1\. 能吃進去一個 ISO證書

2\. 在 issuer欄位 直接使用一個模擬的DID:key 

3\. 在 holder欄位 直接使用一個模擬的DID:key

4\. Claim區段 把ISO文件內最重要的宣告 放進去



然後生成VC



就對VC生成有概念了

**為了讓這個小功能具備完整的 VC 規範結構，建議輸出的 JSON 包含以下核心欄位：**

**{**

&#x20; **"@context": \[**

&#x20;   **"https://www.w3.org/2018/credentials/v1"**

&#x20; **],**

&#x20; **"id": "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6",**

&#x20; **"type": \["VerifiableCredential", "IsoCertificationCredential"],**

&#x20; **"issuer": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",**

&#x20; **"issuanceDate": "2026-09-17T10:00:00Z",**

&#x20; **"credentialSubject": {**

&#x20;   **"id": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",**

&#x20;   **"certificationStandard": "ISO 9001:2015",**

&#x20;   **"certificateNumber": "TW-2026-QA-0891",**

&#x20;   **"scope": "Design and manufacture of electronic components",**

&#x20;   **"validUntil": "2029-09-16"**

&#x20; **}**

**}**

**W3C 最新正式 Recommendation 是 Verifiable Credentials Data Model v2.0**

**練習一下生成VC**

