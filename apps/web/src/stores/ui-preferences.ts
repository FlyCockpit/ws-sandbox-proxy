import { create } from "zustand";
import { createJSONStorage, persist } from "zustand/middleware";

interface UiPreferencesState {
  sidebarCollapsed: boolean;
  toggleSidebar: () => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
}

/**
 * Mirror the sidebar preference onto `<html data-sidebar>`. The head bootstrap
 * (`@wssp/config/theme-init`) sets the same attribute before the first paint
 * from this store's persisted value, and the sidebar sizes itself from it, so
 * the server-rendered loading frame and the live sidebar never disagree.
 */
function applySidebarAttribute(collapsed: boolean): void {
  if (typeof document === "undefined") return;
  if (collapsed) document.documentElement.setAttribute("data-sidebar", "collapsed");
  else document.documentElement.removeAttribute("data-sidebar");
}

export const useUiPreferences = create<UiPreferencesState>()(
  persist(
    (set, get) => ({
      sidebarCollapsed: false,
      toggleSidebar: () => {
        const collapsed = !get().sidebarCollapsed;
        applySidebarAttribute(collapsed);
        set({ sidebarCollapsed: collapsed });
      },
      setSidebarCollapsed: (collapsed) => {
        applySidebarAttribute(collapsed);
        set({ sidebarCollapsed: collapsed });
      },
    }),
    {
      name: "ui-preferences",
      storage: createJSONStorage(() => localStorage),
      onRehydrateStorage: () => (state) => {
        if (state) applySidebarAttribute(state.sidebarCollapsed);
      },
    },
  ),
);
