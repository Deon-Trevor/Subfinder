# Subfinder brand assets

<img src="lockup-on-dark.png#gh-dark-mode-only" alt="Subfinder" width="228">
<img src="lockup-on-light.png#gh-light-mode-only" alt="Subfinder" width="228">

## The mark

Three bars joined alternately left and right. It is the letter S, and it is the
shape a result takes on the page: names stacked in a dated ledger. One closed
path, one fill, no gradients, no container. It holds at 16px, which is the only
size that decides whether a mark works.

Geometry is on a 32 grid. Bar thickness 6, gap 3, corner radius 3 on the outer
turns, sharp on the inner ones, and the two free ends fully round — the outline
a 6-wide round-join stroke of the centre line would produce. Nothing here needs
a font, so the mark renders identically everywhere.

## Which file

| File | Use |
| --- | --- |
| `mark.svg` | The mark alone, `fill: currentColor`. Prefer this and set the colour yourself. |
| `mark-on-light.svg` / `mark-on-dark.svg` | Fixed ink for one background, when the consumer cannot set a colour. |
| `mark-sage.svg` | The mark in brand green, for a neutral ground. |
| `lockup.svg` | Mark and wordmark, following the viewer's colour scheme. |
| `lockup-on-light.svg` / `lockup-on-dark.svg` | Fixed ink lockups, plus PNGs at 4x for READMEs. |
| `lockup-sage-on-light.svg` / `lockup-sage-on-dark.svg` | Green mark, ink wordmark. |
| `icon-src.svg`, `icon-apple-src.svg`, `icon-maskable-src.svg` | Sources the shipped PNGs in `web/` are rasterised from. Not served. |

The wordmark is Archivo 800, converted to outlines. It is not live text, so the
lockup does not need the font installed.

## Colour

| Token | Value | Where |
| --- | --- | --- |
| Sage | `#7FC29B` | The mark on dark. The accent everywhere on the page. |
| Sage deep | `#2F7A55` | The mark on light, where the bright green would not hold contrast. |
| Ink | `#0C100E` | Icon ground. |
| Paper | `#EDEFEA` | Light ground. |

## Rules

Keep clear space of one bar height (a sixth of the mark's width) on every side.
Do not add a container, a shadow, an outline, or a gradient. Do not stretch it —
the mark is square and the lockup has one aspect ratio. On a photograph or any
ground that is neither clearly light nor clearly dark, use the solid ink or
paper variant rather than the green.

## Icons in `web/`

`favicon.svg` inverts with the viewer's colour scheme: sage on ink under a light
browser chrome, ink on sage under a dark one, so the tab icon keeps its contrast
either way. The raster sizes cannot carry a media query, so `favicon.ico`,
`apple-touch-icon.png` and the two PWA icons are fixed at sage on ink, which
reads against both. `icon-512-maskable.png` bleeds the ground to the edges and
keeps the mark inside the safe zone the launcher crop leaves.
