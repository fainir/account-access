"""Edit actual computer footage; no generated app screens or slide frames."""

import argparse
import subprocess
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


def caption(path, lines, height, size=26):
    """Render only a caption strip; all app content comes from the recording."""
    canvas = Image.new("RGB", (1080, height), "#111318")
    draw = ImageDraw.Draw(canvas)
    face = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial.ttf", size)
    top = (height - len(lines) * (size + 8)) // 2
    for index, line in enumerate(lines):
        draw.text(((1080 - face.getlength(line)) / 2, top + index * (size + 8)),
                  line, font=face, fill="white")
    canvas.save(path)


def seconds(value):
    parts = value.split(":")
    if len(parts) == 2:
        parts.insert(0, "0")
    hours, minutes, second = parts
    return int(hours) * 3600 + int(minutes) * 60 + float(second)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--voice", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    work = args.output.parent / "work"
    work.mkdir(exist_ok=True)
    header = work / "live-header.png"
    caption(header, [Path("docs/video/claude-live-title.txt").read_text().strip()], 72, 27)
    inputs = ["-loop", "1", "-i", str(header)]
    footer_filters = []
    blocks = Path("docs/video/claude-live.vtt").read_text().split("\n\n")[1:]
    for index, block in enumerate(blocks):
        if not block.strip():
            continue
        timing, *lines = block.strip().splitlines()
        start, end = [seconds(value) for value in timing.split(" --> ")]
        strip = work / f"live-caption-{index}.png"
        caption(strip, lines, 88)
        inputs += ["-loop", "1", "-i", str(strip)]
        footer_filters.append((index + 3, start, end))
    # Keep the real request and response. Shorten the wait while preserving
    # chronological order, and remove black padding from window capture.
    filters = (
        "[0:v]split=3[s0][s1][s2];"
        "[s0]trim=start=5:end=17,setpts=PTS-STARTPTS[v0];"
        "[s1]trim=start=17:end=38,setpts=(PTS-STARTPTS)/1.7[v1];"
        "[s2]trim=start=38:end=60,setpts=PTS-STARTPTS[v2];"
        "[v0][v1][v2]concat=n=3:v=1:a=0,"
        "crop=1680:2040:112:76,scale=1080:1312,fps=30,"
        "pad=1080:1472:0:72:color=0x111318,"
        "tpad=stop_mode=clone:stop_duration=6[base];"
        "[base][2:v]overlay=0:0:shortest=1[header];"
    )
    last = "header"
    for index, start, end in footer_filters:
        name = f"footer{index}"
        filters += (f"[{last}][{index}:v]overlay=0:1384:shortest=1:"
                    f"enable='between(t,{start},{end})'[{name}];")
        last = name
    filters += f"[{last}]null[v];[1:a]aresample=48000,apad[a]"
    subprocess.run([
        "ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
        "-i", str(args.source), "-i", str(args.voice),
        *inputs,
        "-filter_complex", filters, "-map", "[v]", "-map", "[a]",
        "-c:v", "libx264", "-preset", "fast", "-crf", "19",
        "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "160k",
        "-movflags", "+faststart", "-shortest", str(args.output),
    ], check=True)


if __name__ == "__main__":
    main()
