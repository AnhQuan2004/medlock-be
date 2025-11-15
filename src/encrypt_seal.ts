import "dotenv/config";
import { readFile, writeFile } from "node:fs/promises";
import "dotenv/config";
import { EncryptedObject, SealClient, SessionKey } from "@mysten/seal";
import { getFullnodeUrl, SuiClient } from "@mysten/sui/client";
import { decodeSuiPrivateKey } from "@mysten/sui/cryptography";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { Transaction } from "@mysten/sui/transactions";
import { fromHex, toHex } from "@mysten/sui/utils";
import { Logger } from "tslog";
export const logger = new Logger();

const secret = process.env.SUI_PRIVATE_KEY;
if (!secret) {
  throw new Error(
    "Missing or empty SUI_PRIVATE_KEY in .env file. Please ensure it is set correctly.",
  );
}
const { secretKey } = decodeSuiPrivateKey(secret);
export const signer = Ed25519Keypair.fromSecretKey(secretKey);

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required env var ${name}`);
  }
  return value;
}

const packageId = requireEnv("SEAL_PACKAGE_ID");
const allowlistId = requireEnv("SEAL_ALLOWLIST_ID");
const ttlMin = parseInt(process.env.SEAL_TTL_MIN ?? "10", 10);
if (Number.isNaN(ttlMin) || ttlMin <= 0) {
  throw new Error("SEAL_TTL_MIN must be a positive integer");
}

const serverObjectIds = (process.env.SEAL_KEY_SERVERS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
if (serverObjectIds.length === 0) {
  throw new Error("SEAL_KEY_SERVERS must list at least one key server object ID");
}

const suiClient = new SuiClient({ url: getFullnodeUrl("testnet") });
const sealClient = new SealClient({
  suiClient,
  serverConfigs: serverObjectIds.map((id) => ({
    objectId: id,
    weight: 1,
  })),
  verifyKeyServers: false,
});

async function retrievefileblob(path: string): Promise<Uint8Array> {
  const data = await readFile(path);
  return new Uint8Array(data);
}

async function buildTx(id: string) {
  const tx = new Transaction();

  tx.moveCall({
    target: `${packageId}::allowlist::seal_approve`,
    arguments: [tx.pure.vector("u8", fromHex(id)), tx.object(allowlistId)],
  });

  return await tx.build({ client: suiClient, onlyTransactionKind: true });
}

async function main() {

  const nonce = crypto.getRandomValues(new Uint8Array(5));
  logger.info({ nonce });
  const policyobjectbytes = fromHex(allowlistId);
  const idOne = toHex(new Uint8Array([...policyobjectbytes, ...nonce]));
  const id = toHex(policyobjectbytes);

  logger.info({ idOne, id });

  const data = await retrievefileblob("../research_model/output_samples.csv");
  const { encryptedObject: encryptedBytes } = await sealClient.encrypt({
    threshold: 2,
    packageId,
    id,
    data,
  });

  await writeFile("../encrypted_output.bin", encryptedBytes);
  logger.info("Encrypted data written to ../encrypted_output.bin");

  const sessionKey = await SessionKey.create({
    address: signer.toSuiAddress(),
    packageId,
    ttlMin: 10, // TTL of 10 minutes
    suiClient: new SuiClient({ url: getFullnodeUrl("testnet") }),
    signer,
  });
  const txBytes = await buildTx(id);

  const parsedencryptedblob = EncryptedObject.parse(encryptedBytes);
  await sealClient.fetchKeys({
    ids: [parsedencryptedblob.id],
    txBytes,
    sessionKey,
    threshold: 2,
  });
  // const decryptedFile = await sealClient.decrypt({
  //   data: encryptedBytes,
  //   sessionKey,
  //   txBytes,
  // });

  // const decodedData = new TextDecoder().decode(decryptedFile);

  // logger.info({ decodedData });
}

main().catch(console.error);
