import "dotenv/config";
import express, { type Request } from "express";
import multer from "multer";
import { readFile } from "fs/promises";
import { SuiClient, getFullnodeUrl } from "@mysten/sui/client";
import { decodeSuiPrivateKey } from "@mysten/sui/cryptography";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { WalrusClient } from "@mysten/walrus";
import { SealClient, SessionKey, EncryptedObject } from "@mysten/seal";
import { fromHex, toHex } from "@mysten/sui/utils";
import { Transaction } from "@mysten/sui/transactions";

type UploadRequest = Request & {
  files?: Express.Multer.File[] | { [fieldname: string]: Express.Multer.File[] };
};

const app = express();
app.use(express.json());
const upload = multer({ storage: multer.memoryStorage() });

const secret = process.env.SUI_PRIVATE_KEY!;
const { secretKey } = decodeSuiPrivateKey(secret);
const signer = Ed25519Keypair.fromSecretKey(secretKey);

const packageId = process.env.SEAL_PACKAGE_ID!;
const allowlistId = process.env.SEAL_ALLOWLIST_ID!;
const ttlMin = 10;
const keyServers = process.env.SEAL_KEY_SERVERS!.split(",");

const suiClient = new SuiClient({ url: getFullnodeUrl("testnet") });

const sealClient = new SealClient({
  suiClient,
  serverConfigs: keyServers.map((id) => ({ objectId: id, weight: 1 })),
  verifyKeyServers: false,
});

const walrusClient = new WalrusClient({
  suiClient,
  network: "testnet",
});

async function buildTx(id: string) {
  const tx = new Transaction();
  tx.moveCall({
    target: `${packageId}::allowlist::seal_approve`,
    arguments: [tx.pure.vector("u8", fromHex(id)), tx.object(allowlistId)],
  });

  return tx.build({ client: suiClient, onlyTransactionKind: true });
}

app.post("/upload", upload.any(), async (req, res) => {
  try {
    const uploadReq = req as UploadRequest;
    const normalizedFiles = Array.isArray(uploadReq.files)
      ? uploadReq.files
      : uploadReq.files
        ? Object.values(uploadReq.files).flat()
        : [];
    const file = normalizedFiles[0];
    if (!file) return res.status(400).json({ error: "No file uploaded" });

    const data = file.buffer;
    const nonce = crypto.getRandomValues(new Uint8Array(5));
    const policyBytes = fromHex(allowlistId);
    const id = toHex(new Uint8Array([...policyBytes, ...nonce]));

    const { encryptedObject } = await sealClient.encrypt({
      threshold: 2,
      packageId,
      id,
      data,
    });

    const { blobId } = await walrusClient.writeBlob({
      blob: encryptedObject,
      deletable: false,
      epochs: 3,
      signer,
    });

    return res.json({
      blobId,
      sealId: EncryptedObject.parse(encryptedObject).id,
    });
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    return res.status(500).json({ error: message });
  }
});

app.get("/download/:blobId", async (req, res) => {
  try {
    const blobId = req.params.blobId;
    const encryptedBytes = await walrusClient.readBlob({ blobId });

    const parsed = EncryptedObject.parse(encryptedBytes);
    const sealId = parsed.id;

    const sessionKey = await SessionKey.create({
      address: signer.toSuiAddress(),
      packageId,
      ttlMin,
      suiClient,
      signer,
    });

    const txBytes = await buildTx(sealId);

    await sealClient.fetchKeys({
      ids: [sealId],
      txBytes,
      sessionKey,
      threshold: 2,
    });

    const decrypted = await sealClient.decrypt({
      data: encryptedBytes,
      sessionKey,
      txBytes,
    });

    res.send(new TextDecoder().decode(decrypted));
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    res.status(500).json({ error: message });
  }
});

app.listen(3000, () => console.log("API running on port 3000"));
