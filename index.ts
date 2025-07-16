import { Ed25519KeyIdentity } from "@dfinity/identity";
import { Ed25519PublicKey } from "@dfinity/agent";
import { Principal } from "@dfinity/principal";

// SISI CLIENT
async function client_side() {
  const data = { exp: Math.floor(Date.now() / 1000) + 1000 };
  const identity = await Ed25519KeyIdentity.generate();
  const data_json = JSON.stringify(data);
  const data_buffer = Buffer.from(data_json);
  const data_base64 = data_buffer.toBase64();

  const signature = await identity.sign(data_buffer.buffer);
  const signature_base64 = Buffer.from(signature).toBase64();

  const pubkey_der = identity.getPublicKey().toDer();
  const pubkey_base64 = Buffer.from(pubkey_der).toBase64();

  return {
    data: data_base64,
    signature: signature_base64,
    pubkey: pubkey_base64,
  };
}

// SISI SERVER
async function backend_side(
  data_b64: string,
  signature_b64: string,
  pubkey_b64: string
) {
  const pubkey = Ed25519PublicKey.fromDer(
    Buffer.from(pubkey_b64, "base64").buffer
  ).toRaw();
  const data = Buffer.from(data_b64, "base64").buffer;
  const signature = Buffer.from(signature_b64, "base64").buffer;

  if (Ed25519KeyIdentity.verify(signature, data, pubkey)) {
    const data_parsed = JSON.parse(Buffer.from(data).toString());
    if (data_parsed["exp"] > Math.floor(Date.now() / 1000)) {
      const id = Principal.selfAuthenticating(pubkey as any).toText();
      console.log("Login as: " + id);
      //   QUERY KE DATABASE BERI RESPONSE
    }
  } else {
    console.error("gagal login");
  }
}

const { data, signature, pubkey } = await client_side();

await backend_side(data, signature, pubkey);
