// @vitest-environment jsdom
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@wssp/ui/components/dialog";
import { RadioGroup, RadioGroupItem } from "@wssp/ui/components/radio-group";
import { ResponsiveDialog } from "@wssp/ui/components/responsive-dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@wssp/ui/components/select";
import { useState } from "react";
import { afterEach, expect, it, vi } from "vitest";

// Integration coverage lives in web, which already owns the DOM testing tools.
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function ExpiryActionExample() {
  const [value, setValue] = useState("stop");
  return (
    <RadioGroup aria-label="Expiry action" value={value} onValueChange={setValue}>
      <label>
        <RadioGroupItem value="stop" />
        Stop
      </label>
      <label>
        <RadioGroupItem value="destroy" />
        Destroy
      </label>
    </RadioGroup>
  );
}

function ResponsiveDetailsExample() {
  const [open, setOpen] = useState(true);
  return (
    <ResponsiveDialog
      open={open}
      onOpenChange={setOpen}
      title="Miembros del grupo"
      description="Hosts disponibles"
      closeLabel="Cerrar"
      footer={
        <button type="button" onClick={() => setOpen(false)}>
          Listo
        </button>
      }
    >
      <p>Development East</p>
    </ResponsiveDialog>
  );
}

function NestedCreateExample() {
  const [open, setOpen] = useState(true);
  const [creating, setCreating] = useState(false);
  return (
    <ResponsiveDialog
      open={open}
      onOpenChange={setOpen}
      title="Members"
      description="Host group"
      closeLabel="Close details"
      footer={
        <button type="button" onClick={() => setOpen(false)}>
          Done
        </button>
      }
    >
      <button type="button" onClick={() => setCreating(true)}>
        Add host
      </button>
      <Dialog open={creating} onOpenChange={setCreating}>
        <DialogContent closeLabel="Close create">
          <DialogTitle>Add a host</DialogTitle>
          <DialogDescription>Choose a host</DialogDescription>
          <Select defaultValue="alpha">
            <SelectTrigger aria-label="Host">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="alpha">Alpha</SelectItem>
              <SelectItem value="beta">Beta</SelectItem>
            </SelectContent>
          </Select>
        </DialogContent>
      </Dialog>
    </ResponsiveDialog>
  );
}

it("radio rows expose labels, selected state and keyboard navigation", async () => {
  const user = userEvent.setup();
  render(<ExpiryActionExample />);
  const stop = screen.getByRole("radio", { name: "Stop" });
  expect(stop.getAttribute("aria-checked")).toBe("true");
  await user.click(screen.getByRole("radio", { name: "Destroy" }));
  expect(screen.getByRole("radio", { name: "Destroy" }).getAttribute("aria-checked")).toBe("true");
  await user.keyboard("{ArrowUp}");
  expect(stop.getAttribute("aria-checked")).toBe("true");
});

it("details switch between dialog and drawer at the breakpoint and close through the translated action", async () => {
  let desktop = true;
  const listeners = new Set<() => void>();
  vi.stubGlobal("matchMedia", () => ({
    matches: desktop,
    addEventListener: (_name: string, callback: () => void) => listeners.add(callback),
    removeEventListener: (_name: string, callback: () => void) => listeners.delete(callback),
  }));
  const user = userEvent.setup();
  render(<ResponsiveDetailsExample />);
  const dialog = screen.getByRole("dialog", { name: "Miembros del grupo" });
  expect(dialog.getAttribute("data-slot")).toBe("dialog-content");
  expect(screen.getByRole("button", { name: "Cerrar" })).toBeTruthy();
  await act(async () => {
    desktop = false;
    for (const listener of listeners) listener();
  });
  const drawer = screen.getByRole("dialog", { name: "Miembros del grupo" });
  expect(drawer.getAttribute("data-slot")).toBe("drawer-content");
  expect(screen.getByText("Development East")).toBeTruthy();
  await user.click(screen.getByRole("button", { name: "Listo" }));
  expect(screen.queryByRole("dialog")).toBeNull();
});

it("Escape closes only the top select or create dialog inside mobile details", async () => {
  vi.stubGlobal("matchMedia", () => ({
    matches: false,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  }));
  const user = userEvent.setup();
  render(<NestedCreateExample />);
  await user.click(screen.getByRole("button", { name: "Add host" }));
  await user.click(screen.getByRole("combobox", { name: "Host" }));
  await screen.findByRole("listbox");
  await user.keyboard("{Escape}");
  await waitFor(() => expect(screen.queryByRole("listbox")).toBeNull());
  expect(screen.getByRole("dialog", { name: "Add a host" })).toBeTruthy();
  await user.keyboard("{Escape}");
  await waitFor(() => expect(screen.queryByRole("dialog", { name: "Add a host" })).toBeNull());
  expect(screen.getByRole("dialog", { name: "Members" })).toBeTruthy();
  await user.click(screen.getByRole("button", { name: "Done" }));
  expect(screen.queryByRole("dialog")).toBeNull();
});

it("keeps a long translated confirmation inside safe-area bounds with reachable actions", async () => {
  const { createInstance } = await import("i18next");
  const { I18nextProvider } = await import("react-i18next");
  const { default: common } = await import("@wssp/locales/src/es-MX/common.json");
  const { ConfirmDeleteDialog } = await import("@/components/confirm-delete-dialog");
  const i18n = createInstance();
  await i18n.init({
    lng: "es-MX",
    resources: { "es-MX": { common } },
    react: { useSuspense: false },
  });
  const onConfirm = vi.fn();
  const token = "sandbox-con-un-nombre-muy-largo-para-confirmar-la-eliminacion";
  const user = userEvent.setup();
  render(
    <I18nextProvider i18n={i18n}>
      <ConfirmDeleteDialog
        open
        onOpenChange={vi.fn()}
        title="Eliminar sandbox"
        description={"Confirma la eliminación del sandbox y sus datos. ".repeat(30)}
        confirmToken={token}
        typePrompt="Escribe el nombre para confirmar"
        copyAriaLabel="Copiar nombre"
        onConfirm={onConfirm}
      />
    </I18nextProvider>,
  );
  const dialog = screen.getByRole("alertdialog");
  const classes = dialog.className;
  expect(classes).toContain(
    "max-h-[calc(100dvh-var(--safe-area-top)-var(--safe-area-bottom)-2rem)]",
  );
  expect(classes).toContain("overflow-y-auto");
  expect(classes).toContain("overflow-x-hidden");
  expect(classes).toContain("overscroll-contain");
  expect(classes).toContain("w-[calc(100%-var(--safe-area-left)-var(--safe-area-right)-2rem)]");
  expect(screen.getByRole("button", { name: common.actions.cancel })).toBeTruthy();
  const submit = screen.getByRole("button", { name: common.actions.delete });
  expect((submit as HTMLButtonElement).disabled).toBe(true);
  await user.type(screen.getByRole("textbox"), token);
  await user.click(submit);
  expect(onConfirm).toHaveBeenCalledWith(token);
});
