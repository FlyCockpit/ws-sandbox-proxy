import { Link } from "@tanstack/react-router";
import { env } from "@wssp/env/web";

import type { APP_HOME } from "@/lib/app-home";
import { APP_LOGO } from "@/lib/app-logo";

/**
 * The app name at the start of both header rows (the app shell's `Header` and
 * the public `PublicHeader`), so the two can never size it differently.
 *
 * The name only takes the room the rest of the row leaves it, so it is the
 * first thing to give way: the controls neither wrap to a second row nor run
 * past the header's trailing line while the name can still shrink, whatever
 * the name's length, the width or the locale. Its flex basis is 0
 * (`basis-0 grow`): it grows into what is left after the controls, up to its
 * own width (`max-w-fit`), and never below a 44px target (`min-w-11`). A
 * shrink factor cannot do this: CSS has no shrink order, and the rows wrap on
 * the items' basis, so any larger basis or minimum moves the controls to a
 * second row first. With a MainNav in the row the two share what is left. The
 * span's caps (160px, 224px from `sm:`, 320px from `lg:`) keep a long name
 * from taking the MainNav's room. A name that does not fit ends in an
 * ellipsis (the `truncate` span: an ellipsis needs a block box, and `truncate`
 * on the inline-flex link only clips), and the full name is the link's
 * `title`.
 *
 * The logo comes first (lib/app-logo.ts, docs/design/shell-rules.md § Logo
 * slot): an `<img>` with its 32px box declared, so nothing moves when it
 * loads, and the same element in the server-rendered first frame
 * (`AppShellPending` renders this header too), so it never pops in. Its `alt`
 * is the app name and the visible name is `aria-hidden`, so the link's
 * accessible name is the name once, not twice. It never shrinks: below the
 * name's room the name gives way.
 *
 * `to`: the signed-in home for a signed-in visitor (never the public landing
 * page, which offers "Sign in"), the landing page otherwise.
 */
export function AppNameLink({ to, lang }: { to: typeof APP_HOME | "/$lang"; lang: string }) {
  const appName = env.VITE_APP_NAME;
  return (
    <Link
      to={to}
      params={{ lang }}
      className="inline-flex min-h-11 min-w-11 max-w-fit grow basis-0 items-center gap-2 font-semibold text-lg"
      title={appName}
    >
      <img
        src={APP_LOGO.src}
        srcSet={APP_LOGO.srcSet}
        sizes={APP_LOGO.sizes}
        width={APP_LOGO.size}
        height={APP_LOGO.size}
        alt={appName}
        decoding="async"
        className="size-8 shrink-0 rounded-md"
      />
      <span aria-hidden="true" className="max-w-40 truncate sm:max-w-56 lg:max-w-80">
        {appName}
      </span>
    </Link>
  );
}
