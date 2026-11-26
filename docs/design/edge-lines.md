# Dashboard edge lines

The alignment lines the dashboard shell follows, measured on ink (glyph and
icon bounds, or a boxed control's box) at 390px and 1440px, light and dark.
This page records the lines shared by every container and the lines specific
to wssp areas. Change a value only with maintainer approval, and record the
new value here.

Terms: the **text line** is where labels, headings and bare icons start; the
**box line** is where filled, bordered or shadowed controls start; the
**trailing line** is where the last item in a row ends; the **centre line** is
the horizontal line every item in a bar centres on. An item is within
tolerance when its ink is within 1px of its line.

## Shared lines

| Container                                                           | Text line                                                                                                                                                | Box line                                                                         | Trailing line                                     | Centre / icon column                                                                                                                                     |
| ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| App header (`Header`)                                               | 16px inside the safe-area-adjusted frame                                                                                                                 | —                                                                                | 16px: the last header control's box ends here     | Every header item centres on the header row.                                                                                                             |
| Page content (`DashboardFrame` content column, `PageShell`, `px-4`) | 16px inside the container                                                                                                                                | Same as the text line: buttons, segmented controls, inputs and cards start on it | 16px: header actions and the cards below end here | —                                                                                                                                                        |
| Card (`rounded-xl border p-4`, `Card`)                              | 16px inside the card                                                                                                                                     | Same as the card's text line                                                     | 16px: row actions end here                        | A card title with an icon puts the icon on the text line.                                                                                                |
| Dialog (`DialogContent p-4`)                                        | 16px                                                                                                                                                     | Same as the text line                                                            | 16px: the close X's glyph ink ends on this line   | The close X (a 44px `icon-touch` button at `top-1 right-0`, every width) centres on the title line.                                                      |
| Sheet (`SheetContent`, header `p-4`)                                | 16px inside the border                                                                                                                                   | Same as the text line                                                            | 16px: the close X's glyph ink ends on this line   | The 44px close button at `top-1 right-0` centres on the title line.                                                                                      |
| Dropdown menu (`DropdownMenuContent p-1`, item `px-1.5`)            | 32px when any row has an icon (icon + `gap-1.5`, the same as `inset`); rows without an icon in such a menu take `inset`. A menu with no icons uses 10px. | —                                                                                | —                                                 | The icon column sits 10px in (`size-4`, no extra margin on the icon). Group labels and the account identity line start on the icon column's edge (10px). |

Two rules decide the cases the table does not list: boxes share the text line
inside pages, cards and forms (a 16px card padding leaves no room to outdent a
box), and a miss is fixed in the container (padding, `inset`, or the close
button's placement), never with a one-off margin on one item.

## Area-specific lines

| Container                                                         | Lines                                                                                                                                                                                                                                                                                                         |
| ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Dashboard sidebar (`DashboardFrame` `aside`, `md:` and up)        | Item boxes start 8px inside the sidebar (`px-2` on the nav); icons sit on one column 15px inside the box (23px from the sidebar edge); labels follow after the icon and `gap-2`. The collapse button's box ends 8px from the sidebar's trailing edge (`p-2`). Collapsed, every icon centres on the 64px rail. |
| Admin area                                                        | The admin tab strip, the 2FA banner and every admin page share the page column's (`PAGE_COLUMN_CLASS`, `max-w-7xl`) 16px line, like every other signed-in page (`DashboardFrame`'s content column is the same tier).                                                                                          |
| Onboarding checklist, hosts enrolment card, deployment setup card | Cards: 16px text line; steps are rows of the card (`rounded-lg border p-3` rows inside the card keep a 12px inner line, like `Card size="sm"`).                                                                                                                                                               |

## How it was measured

Measured on 2026-11-22 with a gridlines probe on every dashboard page and
overlay at 1440 and 390 (mobile emulation), light and dark. The probe skips
`aria-hidden` icons, so the close buttons and menu icons were measured from
the DOM: the dialog and sheet close button's glyph ink sits 16.7px in and
centred on the title line.
