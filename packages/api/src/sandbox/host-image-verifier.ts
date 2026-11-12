export type VerifiedHostImage = {
  incusFingerprint: string;
  architecture: string;
  /** Compressed size and format when the host reports them (peer placement facts). */
  sizeBytes?: number;
  format?: "unified" | "split";
};

export type HostImageVerifier = (input: {
  ownerId: string;
  hostId: string;
  imageRef: string;
  expectedArchitecture: string;
}) => Promise<VerifiedHostImage>;

/**
 * The connected host answered and refused the image (not a VM
 * image, architecture differs, incomplete answer). Every other verifier
 * failure means the host could not answer (not connected, credential
 * inactive, busy, timed out) and registration may be retried.
 */
export class HostImageRejected extends Error {
  override name = "HostImageRejected";
}

export class HostImageMissing extends Error {
  override name = "HostImageMissing";
}

let hostImageVerifier: HostImageVerifier | null = null;

/** Bound by the relay server at startup; API services fail closed until then. */
export function bindHostImageVerifier(verifier: HostImageVerifier | null): void {
  hostImageVerifier = verifier;
}

export async function verifyHostImageRegistration(input: {
  ownerId: string;
  hostId: string;
  imageRef: string;
  expectedArchitecture: string;
}): Promise<VerifiedHostImage> {
  if (!hostImageVerifier) {
    throw new Error("host image verifier is not configured");
  }
  return hostImageVerifier(input);
}

export type LiveProbeState = "guest_ready" | "stopped" | "confirmed_absent" | "unreachable";
export type HostSandboxProbeInput = {
  incusFingerprint: string;
  ownerId: string;
  hostId: string;
  sandboxId: string;
  generation: number;
  architecture: string;
  guestUid: number;
  guestGid: number;
  guestHome: string;
  guestShell: string;
};
let hostSandboxProbe: ((input: HostSandboxProbeInput) => Promise<LiveProbeState>) | null = null;
export function bindHostSandboxProbe(probe: typeof hostSandboxProbe): void {
  hostSandboxProbe = probe;
}
export async function probeHostSandbox(input: HostSandboxProbeInput): Promise<LiveProbeState> {
  if (!hostSandboxProbe) return "unreachable";
  // The daemon parses `sandbox.probe.request` with deny_unknown_fields and drops
  // the whole relay session on a stray key, so forward exactly these fields.
  const request: HostSandboxProbeInput = {
    incusFingerprint: input.incusFingerprint,
    ownerId: input.ownerId,
    hostId: input.hostId,
    sandboxId: input.sandboxId,
    generation: input.generation,
    architecture: input.architecture,
    guestUid: input.guestUid,
    guestGid: input.guestGid,
    guestHome: input.guestHome,
    guestShell: input.guestShell,
  };
  try {
    return await hostSandboxProbe(request);
  } catch {
    return "unreachable";
  }
}
