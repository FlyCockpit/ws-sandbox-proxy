import { useInfiniteQuery } from "@tanstack/react-query";
import { SelectItem } from "@wssp/ui/components/select";
import { useId } from "react";
import { useTranslation } from "react-i18next";
import { FormSelect } from "@/components/form-select";
import { InlineRetry } from "@/components/inline-retry";
import { LoadMore } from "@/components/load-more";
import { orpc } from "@/utils/orpc";
import { SharingNotice } from "./pool-sharing";

const paging = {
  initialPageParam: undefined as string | undefined,
  getNextPageParam: (page: { nextCursor: string | null }) => page.nextCursor ?? undefined,
};
export function PoolImageTarget({
  poolId,
  memberId,
  onChange,
}: {
  poolId: string;
  memberId: string;
  onChange: (target: { poolId: string; memberId: string }) => void;
}) {
  const { t } = useTranslation("hosts");
  const poolLabel = useId();
  const memberLabel = useId();
  const pools = useInfiniteQuery({
    ...orpc.sandboxPools.listUsable.infiniteOptions({
      ...paging,
      input: (cursor: string | undefined) => ({ cursor, limit: 100 }),
    }),
    meta: { skipGlobalErrorToast: true },
  });
  const members = useInfiniteQuery({
    ...orpc.sandboxPools.listUsableMembers.infiniteOptions({
      ...paging,
      input: (cursor: string | undefined) => ({ cursor, limit: 100, poolId }),
    }),
    enabled: !!poolId,
    meta: { skipGlobalErrorToast: true },
  });
  return (
    <fieldset className="flex min-w-0 flex-col gap-3">
      <legend>{t("hosts:sharing.imageTarget")}</legend>
      <SharingNotice />
      <p>{t("hosts:sharing.imageNotice")}</p>
      <label htmlFor={poolLabel}>{t("hosts:sharing.choosePool")}</label>
      <FormSelect
        id={poolLabel}
        autoComplete="off"
        value={poolId}
        onValueChange={(value) => onChange({ poolId: value, memberId: "" })}
      >
        <SelectItem value="">{t("hosts:sharing.choosePool")}</SelectItem>
        {pools.data?.pages
          .flatMap((p) => p.items)
          .map((pool) => (
            <SelectItem key={pool.id} value={pool.id}>
              {pool.label} · {"owner" in pool ? pool.owner?.name : t("hosts:sharing.owned")} ·{" "}
              {pool.id}
            </SelectItem>
          ))}
      </FormSelect>
      <LoadMore
        hasNextPage={pools.hasNextPage}
        isFetchingNextPage={pools.isFetchingNextPage}
        onLoadMore={() => void pools.fetchNextPage()}
      />
      <label htmlFor={memberLabel}>{t("hosts:sharing.chooseMember")}</label>
      <FormSelect
        id={memberLabel}
        autoComplete="off"
        value={memberId}
        disabled={!poolId}
        onValueChange={(value) => onChange({ poolId, memberId: value })}
      >
        <SelectItem value="">{t("hosts:sharing.chooseMember")}</SelectItem>
        {members.data?.pages
          .flatMap((p) => p.items)
          .map((member, index) => (
            // Members stay anonymous on purpose (another account's host);
            // they are numbered in list order, never named or linked.
            <SelectItem key={member.id} value={member.id}>
              {t("hosts:sharing.memberOption", { n: index + 1 })}
            </SelectItem>
          ))}
      </FormSelect>
      <LoadMore
        hasNextPage={members.hasNextPage}
        isFetchingNextPage={members.isFetchingNextPage}
        onLoadMore={() => void members.fetchNextPage()}
      />
      {pools.isError || members.isError ? (
        <InlineRetry
          message={t("hosts:pools.failed")}
          onRetry={() => {
            void pools.refetch();
            if (poolId) void members.refetch();
          }}
        />
      ) : null}
    </fieldset>
  );
}
