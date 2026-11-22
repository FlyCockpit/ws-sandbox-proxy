# Third-Party Notices

This project bundles or depends on third-party components whose licenses
require attribution or carry obligations worth knowing about. Other dependencies use permissive licenses such as MIT, Apache-2.0, ISC
and BSD; retain their required license and copyright notices when redistributing.
Full license texts ship inside each package in `node_modules/`.

## Inter (webfont) — SIL Open Font License 1.1

The web app bundles the Inter variable font via
[`@fontsource-variable/inter`](https://www.npmjs.com/package/@fontsource-variable/inter)
(`packages/ui/src/styles/globals.css`, `apps/web/src/routes/__root.tsx`). The
`.woff2` files are emitted into the client build.

> Copyright 2016 The Inter Project Authors
> (https://github.com/rsms/inter)
>
> This Font Software is licensed under the SIL Open Font License, Version 1.1.
> The full license text is available at http://scripts.sil.org/OFL and ships
> with the package at `node_modules/@fontsource-variable/inter/LICENSE`.

The OFL permits bundling the font in commercial products. Its two obligations:
the font files may not be sold on their own, and this notice must accompany
redistributions of the font. Keep this file (or an equivalent notice) if you
ship the bundled font.

## web-tree-sitter and tree-sitter-bash — MIT

The Claude Code PreToolUse hook (`scripts/claude-hooks/pre-tool-use.mjs`) uses
[`web-tree-sitter`](https://www.npmjs.com/package/web-tree-sitter) and
[`tree-sitter-bash`](https://www.npmjs.com/package/tree-sitter-bash) as root
devDependencies to parse Bash at the tool boundary. This is local agent tooling
only — nothing in the web app, server, or worker imports these
packages. The shipped `tree-sitter-bash.wasm` grammar is loaded from the
installed package; no native binding is built (`allowBuilds.tree-sitter-bash:
false` in `pnpm-workspace.yaml`).

## caniuse-lite — CC-BY-4.0

Browser-compatibility data from [caniuse.com](https://caniuse.com), used at
build time by the CSS toolchain (browserslist). The data can also remain in
the production dependency closure with Prisma tooling; preserve its attribution
and package license when redistributing it.

## web-push — Mozilla Public License 2.0

The API uses [web-push](https://github.com/web-push-libs/web-push) for push
notifications; its unmodified JavaScript source ships in the server image
(and the API dependency closure in the worker image). Preserve its notice:

> Copyright 2015 Marco Castelluccio
>
> This Source Code Form is subject to the terms of the Mozilla Public
> License, v. 2.0. If a copy of the MPL was not distributed with this
> file, You can obtain one at http://mozilla.org/MPL/2.0/.

The notice ships at `node_modules/web-push/LICENSE`. The corresponding source
is included in the installed package and available from the
[upstream repository](https://github.com/web-push-libs/web-push).
MPL obligations apply to covered files and modifications to them; the larger
application remains MIT-licensed.

## Lightning CSS — Mozilla Public License 2.0

The production dependency closure includes `lightningcss` and its platform
binary package through Prisma's tooling. These packages carry MPL-2.0 in their
`LICENSE` files. Preserve those files when distributing server and worker
images. The [Lightning CSS source](https://github.com/parcel-bundler/lightningcss)
is available under the [Mozilla Public License 2.0](https://www.mozilla.org/MPL/2.0/).
This also covers the corresponding platform packages on other image architectures.

## elkjs — Eclipse Public License 2.0

Prisma tooling brings [elkjs](https://github.com/kieler/elkjs) into the server,
worker dependency closures. Its full EPL-2.0 text ships in
`node_modules/elkjs/LICENSE.md`; preserve it in redistribution. The package's
JavaScript source is included, with the corresponding
[Eclipse Layout Kernel source](https://github.com/eclipse-elk/elk) and
[elkjs build source](https://github.com/kieler/elkjs) available upstream.

## Runtime dependency review

The production server and worker dependency graphs were checked with
`pnpm licenses list --prod --json` and the filtered production dependency trees.
The additional file-level copyleft notices are web-push, Lightning CSS and
elkjs above. sharp/libvips are outside these production closures. The
caniuse-lite data notice above also applies to copies retained with tooling.

## russh — Apache License 2.0, modified

The Linux CLI (`wssp ssh --stdio`) links russh 0.65.4
(<https://github.com/warp-tech/russh>), Copyright Pierre-Étienne Meunier and the
russh contributors, licensed under
the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
The complete licence text is bundled: `licenses/Apache-2.0.txt` in the source tree,
and `Apache-2.0.txt` next to this file in the CLI release archives.
This project ships a modified copy: `third_party/russh-0.65.4` is the published
crate plus `third_party/russh-0.65.4.patch` (`NOTICE-wssp.md` there lists the changed
files). The change adds a server option under which a channel's receive window grows
only when the application grants it; nothing else in the library changes.

## musl libc — MIT and component notices

Linux CLI archives statically link musl libc. The upstream copyright and
component notices follow (https://git.musl-libc.org/cgit/musl/plain/COPYRIGHT).

```text
musl as a whole is licensed under the following standard MIT license:

----------------------------------------------------------------------
Copyright © 2005-2020 Rich Felker, et al.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
----------------------------------------------------------------------

Authors/contributors include:

A. Wilcox
Ada Worcester
Alex Dowad
Alex Suykov
Alexander Monakov
Andre McCurdy
Andrew Kelley
Anthony G. Basile
Aric Belsito
Arvid Picciani
Bartosz Brachaczek
Benjamin Peterson
Bobby Bingham
Boris Brezillon
Brent Cook
Chris Spiegel
Clément Vasseur
Daniel Micay
Daniel Sabogal
Daurnimator
David Carlier
David Edelsohn
Denys Vlasenko
Dmitry Ivanov
Dmitry V. Levin
Drew DeVault
Emil Renner Berthing
Fangrui Song
Felix Fietkau
Felix Janda
Gianluca Anzolin
Hauke Mehrtens
He X
Hiltjo Posthuma
Isaac Dunham
Jaydeep Patil
Jens Gustedt
Jeremy Huntwork
Jo-Philipp Wich
Joakim Sindholt
John Spencer
Julien Ramseier
Justin Cormack
Kaarle Ritvanen
Khem Raj
Kylie McClain
Leah Neukirchen
Luca Barbato
Luka Perkov
Lynn Ochs
M Farkas-Dyck (Strake)
Mahesh Bodapati
Markus Wichmann
Masanori Ogino
Michael Clark
Michael Forney
Mikhail Kremnyov
Natanael Copa
Nicholas J. Kain
orc
Pascal Cuoq
Patrick Oppenlander
Petr Hosek
Petr Skocik
Pierre Carrier
Reini Urban
Rich Felker
Richard Pennington
Ryan Fairfax
Samuel Holland
Segev Finer
Shiz
sin
Solar Designer
Stefan Kristiansson
Stefan O'Rear
Szabolcs Nagy
Timo Teräs
Trutz Behn
Will Dietz
William Haddon
William Pitcock

Portions of this software are derived from third-party works licensed
under terms compatible with the above MIT license:

The TRE regular expression implementation (src/regex/reg* and
src/regex/tre*) is Copyright © 2001-2008 Ville Laurikari and licensed
under a 2-clause BSD license (license text in the source files). The
included version has been heavily modified by Rich Felker in 2012, in
the interests of size, simplicity, and namespace cleanliness.

Much of the math library code (src/math/* and src/complex/*) is
Copyright © 1993,2004 Sun Microsystems or
Copyright © 2003-2011 David Schultz or
Copyright © 2003-2009 Steven G. Kargl or
Copyright © 2003-2009 Bruce D. Evans or
Copyright © 2008 Stephen L. Moshier or
Copyright © 2017-2018 Arm Limited
and labelled as such in comments in the individual source files. All
have been licensed under extremely permissive terms.

The ARM memcpy code (src/string/arm/memcpy.S) is Copyright © 2008
The Android Open Source Project and is licensed under a two-clause BSD
license. It was taken from Bionic libc, used on Android.

The AArch64 memcpy and memset code (src/string/aarch64/*) are
Copyright © 1999-2019, Arm Limited.

The implementation of DES for crypt (src/crypt/crypt_des.c) is
Copyright © 1994 David Burren. It is licensed under a BSD license.

The implementation of blowfish crypt (src/crypt/crypt_blowfish.c) was
originally written by Solar Designer and placed into the public
domain. The code also comes with a fallback permissive license for use
in jurisdictions that may not recognize the public domain.

The smoothsort implementation (src/stdlib/qsort.c) is Copyright © 2011
Lynn Ochs and is licensed under an MIT-style license.

The x86_64 port was written by Nicholas J. Kain and is licensed under
the standard MIT terms.

The mips and microblaze ports were originally written by Richard
Pennington for use in the ellcc project. The original code was adapted
by Rich Felker for build system and code conventions during upstream
integration. It is licensed under the standard MIT terms.

The mips64 port was contributed by Imagination Technologies and is
licensed under the standard MIT terms.

The powerpc port was also originally written by Richard Pennington,
and later supplemented and integrated by John Spencer. It is licensed
under the standard MIT terms.

All other files which have no copyright comments are original works
produced specifically for use as part of this library, written either
by Rich Felker, the main author of the library, or by one or more
contibutors listed above. Details on authorship of individual files
can be found in the git version control history of the project. The
omission of copyright and license comments in each file is in the
interest of source tree size.

In addition, permission is hereby granted for all public header files
(include/* and arch/*/bits/*) and crt files intended to be linked into
applications (crt/*, ldso/dlstart.c, and arch/*/crt_arch.h) to omit
the copyright notice and permission notice otherwise required by the
license, and to use these files without any requirement of
attribution. These files include substantial contributions from:

Bobby Bingham
John Spencer
Nicholas J. Kain
Rich Felker
Richard Pennington
Stefan Kristiansson
Szabolcs Nagy

all of whom have explicitly granted such permission.

This file previously contained text expressing a belief that most of
the files covered by the above exception were sufficiently trivial not
to be subject to copyright, resulting in confusion over whether it
negated the permissions granted in the license. In the spirit of
permissive licensing, and of not having licensing issues being an
obstacle to adoption, that text has been removed.
```
