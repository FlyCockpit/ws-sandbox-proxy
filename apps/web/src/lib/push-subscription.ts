/** Browser subscriptions persist across unmounts; roll back only new, unregistered ones. */
export async function registerPushSubscription(
  manager: Pick<PushManager, "getSubscription" | "subscribe">,
  applicationServerKey: BufferSource,
  persist: (subscription: PushSubscriptionJSON) => Promise<void>,
): Promise<void> {
  const existing = await manager.getSubscription();
  const subscription =
    existing ??
    (await manager.subscribe({
      userVisibleOnly: true,
      applicationServerKey,
    }));
  try {
    await persist(subscription.toJSON());
  } catch (error) {
    if (!existing) {
      // Preserve the registration error even if browser cleanup also fails.
      await subscription.unsubscribe().catch(() => false);
    }
    throw error;
  }
}
