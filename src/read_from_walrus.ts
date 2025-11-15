import "dotenv/config";
import { readFile } from "node:fs/promises";
import fetch from "node-fetch";
import { getFullnodeUrl, SuiClient } from "@mysten/sui/client";
import { decodeSuiPrivateKey } from "@mysten/sui/cryptography";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { WalrusClient } from "@mysten/walrus";
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

const suiClient = new SuiClient({ url: getFullnodeUrl("testnet") });

const tracedFetch = (url: unknown, options?: unknown) => {
  logger.info({ url });
  return fetch(url as any, options as any);
};

const walrusClient = new WalrusClient({
  suiClient: suiClient as any,
  network: "testnet",
  storageNodeClientOptions: {
    fetch: tracedFetch as any,
    timeout: 60_000,
  },
});

async function retrievefileblob(path: string): Promise<Uint8Array> {
  const data = await readFile(path);
  return new Uint8Array(data);
}

async function main() {
  // write
  const data = await retrievefileblob("../research_model/output_samples.csv");

  const { blobId: originBlobId, metadata } =
    await walrusClient.encodeBlob(data);

  const { blobId } = await walrusClient.writeBlob({
    blob: data,
    deletable: false,
    epochs: 3,
    signer,
  });

  console.log({ blobId });
//   const blobId = "BCoAj5ZzSGPJS66Ye3f9ME_jj0ui4MltiuIxY3WMpQQ";
  // const blob = await walrusClient.readBlob({ blobId });
  // const decodedData = new TextDecoder().decode(blob);

  // console.log({ decodedData });

}

main().catch(console.error);
