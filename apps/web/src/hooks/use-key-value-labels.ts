import type { KeyValueEditorLabels } from "@wssp/ui/components/key-value-editor";
import { useTranslation } from "react-i18next";

/** Translated strings for `KeyValueEditor`; `add` names what a row is ("Add variable"). */
export function useKeyValueLabels(add?: string): KeyValueEditorLabels {
  const { t } = useTranslation("common");
  return {
    key: t("keyValue.key"),
    value: t("keyValue.value"),
    add: add ?? t("keyValue.add"),
    remove: (key) => t("keyValue.remove", { key }),
    rowsMode: t("keyValue.rowsMode"),
    textMode: t("keyValue.textMode"),
    textHint: t("keyValue.textHint"),
    show: t("keyValue.show"),
    hide: t("keyValue.hide"),
    problem: (problem, key) => t(`keyValue.problem.${problem}`, { key }),
    lineProblem: (line) => t("keyValue.lineProblem", { line }),
    empty: t("keyValue.empty"),
    unwritableKeys: t("keyValue.unwritableKeys"),
  };
}
