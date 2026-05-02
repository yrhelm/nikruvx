# Screenshots & demo media

Screenshots, GIFs, and the 60-second demo video referenced from the
project README and the Wiki. Drop new ones in here and reference them
with **relative paths** so they survive repo migrations and forks.

## Conventions

| File | Purpose | Recommended size |
|---|---|---|
| `nexus_home.png` | Landing screen with OSI tower + stats | 1920 × 1200 |
| `attack_chain.png` | A CVE detail card with the **Attack Chain** view expanded | 1920 × 1200 |
| `sbom_scan.png` | SBOM scan result panel after dropping a manifest | 1920 × 1200 |
| `posture_matrix.png` | Capability x OSI heat-map with policies loaded | 1920 × 1200 |
| `posture_replay.png` | Per-step BLOCKED / PARTIAL / EXPLOITABLE timeline | 1920 × 1200 |
| `hipaa_summary.png` | HIPAA / Compliance lens dashboard | 1920 × 1200 |
| `clinical_findings.png` | Clinical AI run results with failures visible | 1920 × 1200 |
| `red_team.png` | Red-Team Mode output with chains + LLM brief | 1920 × 1200 |
| `demo.mp4` | 60-second walkthrough video | 1920 × 1080, < 25 MB |
| `demo.gif` | Looping animation derived from `demo.mp4` | 1280 × 720, < 8 MB |

## Capturing on Windows

- **Static screenshots** -- press `Win + Shift + S`, drag the rectangle,
  paste into Paint or open with the Snipping Tool, save as PNG.
- **Recording the 60-second demo** -- use the [OBS Studio](https://obsproject.com/)
  preset *1080p 30fps + AAC 128kbps*, export as MP4, then convert to
  optimized GIF with [ffmpeg](https://ffmpeg.org/) for inline embedding:

  ```powershell
  ffmpeg -i demo.mp4 -vf "fps=15,scale=1280:-1:flags=lanczos" -c:v gif demo.gif
  ```

## Capturing on macOS / Linux

- **Static** -- `Shift+Cmd+4` (mac) or `gnome-screenshot -a` (Linux).
- **Recording** -- macOS `Shift+Cmd+5`, or `simplescreenrecorder` on Linux.

## Style

- Use the **dark theme** (the UI is dark by default, no override needed).
- Crop tightly - aim for ~80% content and ~20% chrome.
- Annotate sparingly. If a screenshot needs annotations, use a soft red
  outline and 14pt sans-serif labels in the same accent color as the UI
  (cyan `#00e5ff`).
- Optimize PNGs with [TinyPNG](https://tinypng.com/) or `pngquant` to
  keep README load time fast.

## Embedding in the README

Use relative paths so they work from forks, git clones, and offline
viewers:

```markdown
![Cyber Nexus home](docs/screenshots/nexus_home.png)
```

For the wiki, drag-drop into the wiki editor instead -- GitHub will
upload to its long-lived asset CDN automatically (see the wiki page
["Embedded image URLs"](../../../wiki) for details).

## Looking for help

The "60-second demo video" item on the **Roadmap** is open
**🤝 community** -- contributions welcome. Tag the PR `screenshot`.
