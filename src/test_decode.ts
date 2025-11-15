import "dotenv/config";
import express, { type Request } from "express";
import { readFile } from "fs/promises";
import { SuiClient, getFullnodeUrl } from "@mysten/sui/client";
import { decodeSuiPrivateKey } from "@mysten/sui/cryptography";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { WalrusClient } from "@mysten/walrus";
import { SealClient, SessionKey, EncryptedObject } from "@mysten/seal";
import { Transaction } from "@mysten/sui/transactions";
import { fromHex, toHex } from "@mysten/sui/utils";
import { Logger } from "tslog";
import multer from "multer";

const logger = new Logger();
const app = express();
app.use(express.json());
const upload = multer({ storage: multer.memoryStorage() });

type UploadRequest = Request & {
  files?: Express.Multer.File[];
};

// -------------------------------
//  SETUP
// -------------------------------
const secret = process.env.SUI_PRIVATE_KEY!;
const { secretKey } = decodeSuiPrivateKey(secret);
const signer = Ed25519Keypair.fromSecretKey(secretKey);

const packageId = process.env.SEAL_PACKAGE_ID!;
const allowlistId = process.env.SEAL_ALLOWLIST_ID!;
const ttlMin = parseInt(process.env.SEAL_TTL_MIN || "10");
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

// -------------------------------
// Helper: Approve Seal session
// -------------------------------
async function buildTx(id: string) {
  const tx = new Transaction();
  tx.moveCall({
    target: `${packageId}::allowlist::seal_approve`,
    arguments: [
      tx.pure.vector("u8", fromHex(id)),
      tx.object(allowlistId),
    ],
  });

  return await tx.build({ client: suiClient, onlyTransactionKind: true });
}

// -------------------------------
//  API: UPLOAD ENCRYPTED FILE
// -------------------------------
app.post("/upload", upload.any(), async (req, res) => {
  try {
    let data: Buffer;
    const files = (req as UploadRequest).files;
    if (files && files.length > 0) {
      data = files[0].buffer;
    } else {
      const { filePath } = req.body as { filePath?: string };
      if (!filePath) {
        return res.status(400).send("file or filePath required");
      }

      data = await readFile(filePath);
    }

    const nonce = crypto.getRandomValues(new Uint8Array(5));
    const policyBytes = fromHex(allowlistId);
    const id = toHex(new Uint8Array([...policyBytes, ...nonce])); // unique seal encrypt id

    // ---------- Encrypt ----------
    const { encryptedObject } = await sealClient.encrypt({
      threshold: 2,
      packageId,
      id,
      data,
    });

    // ---------- Upload encrypted blob to Walrus ----------
    const { blobId } = await walrusClient.writeBlob({
      blob: encryptedObject,
      deletable: false,
      epochs: 3,
      signer,
    });

    return res.json({
      ok: true,
      blobId,
      sealId: EncryptedObject.parse(encryptedObject).id,
    });
  } catch (err) {
    console.error(err);
    res.status(500).send(err.toString());
  }
});

// -------------------------------
//  API: DOWNLOAD + DECRYPT
// -------------------------------
app.get("/download/:blobId", async (req, res) => {
  try {
    const blobId = req.params.blobId;
    const encryptedBytes = await walrusClient.readBlob({ blobId });

    // ---------- Parse SEAL object ----------
    const parsed = EncryptedObject.parse(encryptedBytes);
    const sealId = parsed.id;

    // ---------- Create session key ----------
    const sessionKey = await SessionKey.create({
      address: signer.toSuiAddress(),
      packageId,
      ttlMin,
      suiClient,
      signer,
    });

    // ---------- Build approval tx ----------
    const txBytes = await buildTx(sealId);

    // ---------- Fetch keys from key servers ----------
    await sealClient.fetchKeys({
      ids: [sealId],
      txBytes,
      sessionKey,
      threshold: 2,
    });

    // ---------- Decrypt ----------
    const decrypted = await sealClient.decrypt({
      data: encryptedBytes,
      sessionKey,
      txBytes,
    });

    res.send({
      ok: true,
      decrypted: new TextDecoder().decode(decrypted),
    });
  } catch (err) {
    console.error(err);
    res.status(500).send(err.toString());
  }
});

// -------------------------------
app.listen(3000, () => console.log("Server running on port 3000"));
