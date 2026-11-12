import { expectTypeOf, it } from "vitest";
import type { Principal, sessionPrincipal } from "../contracts";
import type {
  HOST_PROCEDURE_INVENTORY,
  POOL_PROCEDURE_INVENTORY,
  SANDBOX_PROCEDURE_INVENTORY,
  TEMPLATE_PROCEDURE_INVENTORY,
} from "./index";
import type { createSdkKey, listSdkKeys, revokeSdkKey } from "./sdk-keys";

it("every exported service requires an identity-preserving principal", () => {
  type Service =
    | (typeof POOL_PROCEDURE_INVENTORY)[keyof typeof POOL_PROCEDURE_INVENTORY]
    | (typeof HOST_PROCEDURE_INVENTORY)[keyof typeof HOST_PROCEDURE_INVENTORY]
    | (typeof SANDBOX_PROCEDURE_INVENTORY)[keyof typeof SANDBOX_PROCEDURE_INVENTORY]
    | (typeof TEMPLATE_PROCEDURE_INVENTORY)[keyof typeof TEMPLATE_PROCEDURE_INVENTORY]
    | typeof createSdkKey
    | typeof listSdkKeys
    | typeof revokeSdkKey;
  expectTypeOf<Parameters<Service>[0]>().toEqualTypeOf<Principal>();
  expectTypeOf<{ ownerId: string }>().not.toExtend<Principal>();
  expectTypeOf<ReturnType<typeof sessionPrincipal>>()
    .extract<{ kind: "session" }>()
    .not.toBeNever();
});
