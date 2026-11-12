import { screen, within } from "@testing-library/react";
import type userEvent from "@testing-library/user-event";

type User = ReturnType<typeof userEvent.setup>;

export async function openSelect(user: User, trigger: HTMLElement) {
  if (trigger.getAttribute("aria-expanded") !== "true") await user.click(trigger);
  return within(await screen.findByRole("listbox"));
}

/** Choose a portaled option by its accessible name, as a user would. */
export async function selectOption(user: User, trigger: HTMLElement, name: string | RegExp) {
  const popup = await openSelect(user, trigger);
  await user.click(await popup.findByRole("option", { name }));
}

export async function selectChoices(user: User, trigger: HTMLElement) {
  const popup = await openSelect(user, trigger);
  const choices = popup.getAllByRole("option");
  await user.keyboard("{Escape}");
  return choices;
}
