import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import prisma, { type Prisma } from "@wssp/db";
import {
  DATA_KEY_HKDF_SALT,
  type DataKeyPurpose,
  type DataSubkey,
  deriveSubkeys,
  readDataKeyring,
} from "../../crypto/data-key";
import { encodeHmacContext } from "../hmac-context";

/**
 * Preview tunnels (docs/guide/tunnels.md): the one tunnel server the instance
 * admin configured. Optional — no row means the integration is off and every
 * tunnel call is refused with `UNSUPPORTED_CAPABILITY` (`tunnel_off`).
 *
 * The service credential (`tnsvc_…`) is sealed with AES-256-GCM under the
 * `tunnel-service-credential:v1` HKDF sub-key of DATA_ENCRYPTION_KEY. AAD binds
 * it to (row id, API URL): a ciphertext moved to another URL never opens, so
 * changing the URL always needs the credential again.
 */
export const TUNNEL_CREDENTIAL_PURPOSE = "tunnel-service-credential:v1" satisfies DataKeyPurpose;
export const TUNNEL_CONFIG_ID = "default";
const TAG_BYTES = 16;
const NONCE_BYTES = 12;

type TunnelKey = DataSubkey<typeof TUNNEL_CREDENTIAL_PURPOSE>;

/** `https://host[:port]`, lowercase, no path/query/userinfo; null if invalid. */
export function normalizeTunnelApiUrl(raw: string): string | null {
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    return null;
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    (url.pathname !== "/" && url.pathname !== "") ||
    url.search !== "" ||
    url.hash !== "" ||
    url.origin.length > 256 ||
    // The relay and the node accept host names and IPv4 literals only.
    url.hostname.includes(":") ||
    url.hostname.startsWith("[") ||
    // Exactly what the relay's `tunnel.apply` schema carries to the node.
    !/^https:\/\/[A-Za-z0-9][A-Za-z0-9.:-]*$/.test(url.origin)
  )
    return null;
  return url.origin;
}

/** SHA-256 (hex) of a service credential. */
export function credentialSha256(credential: string): string {
  return createHash("sha256").update(credential).digest("hex");
}

/**
 * A new configuration's identity: bound to its URL and credential, and
 * salted so that configuring the same server again after a turn-off is a
 * different identity (nothing from the old one can settle against it).
 */
export function mintServerKey(apiUrl: string, credentialHash: string): string {
  return createHash("sha256")
    .update(
      encodeHmacContext([
        "wssp-tunnel-server:v1",
        apiUrl,
        credentialHash,
        randomBytes(16).toString("hex"),
      ]),
    )
    .digest("hex");
}

/** A tunnel service credential: `tnsvc_` and base64url. */
export function validServiceCredential(value: string): boolean {
  return /^tnsvc_[A-Za-z0-9_-]{16,120}$/.test(value);
}

function aad(apiUrl: string): Buffer {
  return encodeHmacContext([
    DATA_KEY_HKDF_SALT,
    TUNNEL_CREDENTIAL_PURPOSE,
    TUNNEL_CONFIG_ID,
    apiUrl,
  ]);
}

/** The sub-keys (current first) or null when DATA_ENCRYPTION_KEY is unset. */
export function tunnelKeys(): { current: TunnelKey; all: readonly TunnelKey[] } | null {
  let ring: ReturnType<typeof readDataKeyring>;
  try {
    ring = readDataKeyring();
  } catch {
    return null;
  }
  return ring ? deriveSubkeys(ring, TUNNEL_CREDENTIAL_PURPOSE) : null;
}

export type SealedCredential = { ciphertext: Buffer; nonce: Buffer; keyId: string };

export function sealCredential(
  credential: string,
  apiUrl: string,
  key: TunnelKey,
): SealedCredential {
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key.key, nonce, { authTagLength: TAG_BYTES });
  cipher.setAAD(aad(apiUrl));
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(credential, "utf8")),
    cipher.final(),
    cipher.getAuthTag(),
  ]);
  return { ciphertext, nonce, keyId: key.rootKeyId };
}

/** Thrown when the credential cannot be opened. Carries no data. */
export class TunnelCredentialUnavailable extends Error {
  constructor() {
    super("The tunnel service credential is unavailable.");
    this.name = "TunnelCredentialUnavailable";
  }
}

export function openCredential(
  sealed: { ciphertext: Uint8Array; nonce: Uint8Array; keyId: string },
  apiUrl: string,
  keys: readonly TunnelKey[],
): string {
  const key = keys.find((candidate) => candidate.rootKeyId === sealed.keyId);
  const body = Buffer.from(sealed.ciphertext);
  if (!key || body.byteLength <= TAG_BYTES || sealed.nonce.byteLength !== NONCE_BYTES)
    throw new TunnelCredentialUnavailable();
  try {
    const decipher = createDecipheriv("aes-256-gcm", key.key, Buffer.from(sealed.nonce), {
      authTagLength: TAG_BYTES,
    });
    decipher.setAAD(aad(apiUrl));
    decipher.setAuthTag(body.subarray(body.byteLength - TAG_BYTES));
    return Buffer.concat([
      decipher.update(body.subarray(0, body.byteLength - TAG_BYTES)),
      decipher.final(),
    ]).toString("utf8");
  } catch {
    throw new TunnelCredentialUnavailable();
  }
}

/** Projection without ciphertext: what reads may see. */
export const tunnelConfigPublicSelect = {
  apiUrl: true,
  maxTunnelsPerOwner: true,
  disabledAt: true,
  updatedAt: true,
} satisfies Prisma.TunnelServerConfigSelect;

/** Only the controller and the tunnel service open the credential. */
const tunnelConfigSecretSelect = {
  serverKey: true,
  apiUrl: true,
  maxTunnelsPerOwner: true,
  disabledAt: true,
  credentialCiphertext: true,
  credentialNonce: true,
  credentialKeyId: true,
} satisfies Prisma.TunnelServerConfigSelect;

export type TunnelServer = {
  apiUrl: string;
  credential: string;
  maxTunnelsPerOwner: number;
  /** Root kid the credential is sealed under (rewrap when it is not current). */
  keyId: string;
  /** Turning off: only deletions happen until the row is removed. */
  draining: boolean;
  /** This configuration's identity (`TunnelServerConfig.serverKey`). */
  serverKey: string;
};

type Reader = Pick<Prisma.TransactionClient, "tunnelServerConfig">;

/** Whether the integration is on for callers: configured and not turning off. */
export async function tunnelConfigured(client: Reader = prisma): Promise<boolean> {
  const row = await client.tunnelServerConfig.findUnique({
    where: { id: TUNNEL_CONFIG_ID },
    select: { disabledAt: true },
  });
  return row != null && row.disabledAt == null;
}

/**
 * The configured server with its opened credential; null when unconfigured.
 * Throws `TunnelCredentialUnavailable` when the row exists but no configured
 * data key opens it.
 */
export async function readTunnelServer(client: Reader = prisma): Promise<TunnelServer | null> {
  const row = await client.tunnelServerConfig.findUnique({
    where: { id: TUNNEL_CONFIG_ID },
    select: tunnelConfigSecretSelect,
  });
  if (row == null) return null;
  const keys = tunnelKeys();
  if (!keys) throw new TunnelCredentialUnavailable();
  return {
    apiUrl: row.apiUrl,
    maxTunnelsPerOwner: row.maxTunnelsPerOwner,
    keyId: row.credentialKeyId,
    draining: row.disabledAt != null,
    serverKey: row.serverKey,
    credential: openCredential(
      {
        ciphertext: row.credentialCiphertext,
        nonce: row.credentialNonce,
        keyId: row.credentialKeyId,
      },
      row.apiUrl,
      keys.all,
    ),
  };
}
