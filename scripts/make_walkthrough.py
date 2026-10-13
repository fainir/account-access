"""Render the captioned beginner video from its public storyboard and verified evidence.

Requires Python + Pillow, ffmpeg/ffprobe, and macOS `say` for offline narration.
Private logs and temporary narration stay in artifacts/video/work (Git-ignored).
Run only after preparing artifacts/video/evidence.json and the owner screenshots.
This renderer never opens personal accounts or reads credential stores.
"""

import argparse
import hashlib
import json
import math
import shutil
import subprocess
import wave
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts/video"
WORK = OUT / "work"
W, H, FPS = 1920, 1080, 12
INK = "#f3f6f7"
MUTED = "#a6b8c0"
GREEN = "#78e8bd"
PURPLE = "#b7a4fa"
PANEL = "#10252e"
LINE = "#25404b"
FONT = Path("/System/Library/Fonts/Supplemental")


def font(size, *, bold=False, mono=False):
    if mono:
        path = Path("/System/Library/Fonts/Menlo.ttc")
    else:
        path = FONT / ("Arial Bold.ttf" if bold else "Arial.ttf")
    if not path.exists():
        raise RuntimeError("This video renderer needs the documented macOS fonts.")
    return ImageFont.truetype(str(path), size)


def wrap(text, face, width):
    result = []
    for paragraph in text.split("\n"):
        line = ""
        for word in paragraph.split():
            proposal = (line + " " + word).strip()
            if face.getlength(proposal) > width and line:
                result.append(line)
                line = word
            else:
                line = proposal
        result.append(line)
    return result


def block(draw, text, x, y, face, width, *, fill=INK, gap=12):
    lines = wrap(text, face, width)
    for line in lines:
        draw.text((x, y), line, font=face, fill=fill)
        y += face.size + gap
    return y


def box(draw, xy, fill=PANEL, outline=LINE, radius=24):
    draw.rounded_rectangle(xy, radius, fill=fill, outline=outline, width=2)


def clock(value):
    millis = round(value * 1000)
    seconds, ms = divmod(millis, 1000)
    minutes, sec = divmod(seconds, 60)
    hours, minute = divmod(minutes, 60)
    return f"{hours:02}:{minute:02}:{sec:02},{ms:03}"


def clip_duration(path):
    result = subprocess.run(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "json", str(path)],
        capture_output=True, text=True, check=True,
    )
    return float(json.loads(result.stdout)["format"]["duration"])


def prepare_audio(scenes, voice):
    cursor, captions, chapters = 0.0, [], []
    for n, scene in enumerate(scenes):
        voice_key = hashlib.sha256((voice + scene["narration"]).encode()).hexdigest()[:12]
        raw = WORK / f"voice-{n:02}-{voice_key}.aiff"
        text_file = WORK / f"voice-{n:02}.txt"
        text_file.write_text(scene["narration"])
        if not raw.exists():
            subprocess.run(["say", "-v", voice, "-r", "162", "-f", str(text_file), "-o", str(raw)], check=True)
        spoken = clip_duration(raw)
        duration = math.ceil((spoken + 1.5) * FPS) / FPS
        scene.update(duration=duration, spoken=spoken, start=cursor)
        audio = WORK / f"audio-{n:02}.wav"
        subprocess.run([
            "ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-i", str(raw),
            "-af", "adelay=450,apad", "-t", str(duration), "-ar", "48000", "-ac", "1",
            "-c:a", "pcm_s16le", str(audio),
        ], check=True)
        chapters.append({"start": round(cursor, 3), "title": scene["title"], "id": scene["id"]})
        words = scene["narration"].split()
        chunks, chunk = [], []
        for word in words:
            chunk.append(word)
            if len(chunk) >= 14 or (word.endswith((".", "?", "!")) and len(chunk) >= 6):
                chunks.append(" ".join(chunk))
                chunk = []
        if chunk:
            chunks.append(" ".join(chunk))
        weight = sum(len(x) for x in chunks)
        offset = 0.45
        local = []
        for text in chunks:
            length = spoken * len(text) / weight
            caption = {"start": cursor + offset, "end": cursor + offset + length, "text": text}
            captions.append(caption)
            local.append({"start": offset, "end": offset + length, "text": text})
            offset += length
        scene["captions"] = local
        cursor += duration
    with wave.open(str(OUT / "narration.wav"), "wb") as combined:
        combined.setnchannels(1)
        combined.setsampwidth(2)
        combined.setframerate(48000)
        for n in range(len(scenes)):
            with wave.open(str(WORK / f"audio-{n:02}.wav"), "rb") as clip:
                combined.writeframes(clip.readframes(clip.getnframes()))
    srt = []
    for n, item in enumerate(captions, 1):
        srt.append(f"{n}\n{clock(item['start'])} --> {clock(item['end'])}\n{item['text']}\n")
    (OUT / "account-access-walkthrough.en.srt").write_text("\n".join(srt))
    (OUT / "chapters.json").write_text(json.dumps(chapters, indent=2) + "\n")
    return cursor


def base_frame(scene, index, evidence):
    image = Image.new("RGB", (W, H), "#08171f")
    d = ImageDraw.Draw(image)
    d.rounded_rectangle((80, 47, 135, 102), 14, fill=GREEN)
    d.text((90, 62), "AA", font=font(22, bold=True), fill="#08241a")
    d.text((156, 59), "ACCOUNT ACCESS  /  FIRST RUN", font=font(25, bold=True), fill=INK)
    d.text((1370, 61), scene["chapter"], font=font(23, bold=True), fill=GREEN)
    d.text((80, 149), scene["title"], font=font(58, bold=True), fill=INK)
    block(d, scene["subtitle"], 83, 226, font(28), 1770, fill=MUTED)
    d.line((80, 878, 1840, 878), fill=LINE, width=2)
    block(d, scene["note"], 83, 1012, font(21), 1720, fill=MUTED, gap=4)
    kind = scene["kind"]
    if kind in {"intro", "finish"}:
        hero = scene.get("hero", ["Let your agent use", "the access you allow."])
        d.text((84, 340), hero[0], font=font(83, bold=True), fill=INK)
        d.text((84, 437), hero[1], font=font(83, bold=True), fill=GREEN)
        labels = scene.get("labels", ["Connect once", "Choose permissions", "Ask your agent"])
        for i, label in enumerate(labels):
            x = 85 + i * 590
            box(d, (x, 610, x + 554, 764))
            d.text((x + 28, 635), f"0{i + 1}", font=font(25, bold=True), fill=GREEN)
            d.text((x + 28, 685), label, font=font(32, bold=True), fill=INK)
        d.text((86, 803), "github.com/fainir/account-access", font=font(29, mono=True), fill=MUTED)
    elif kind == "cards":
        for i, (title, detail) in enumerate(scene["cards"]):
            x = 84 + 591 * i
            box(d, (x, 343, x + 553, 740))
            d.text((x + 34, 379), f"0{i + 1}", font=font(39, bold=True), fill=GREEN)
            title_face = font(39 if len(title) > 16 else 49, bold=True)
            block(d, title, x + 34, 471, title_face, 475)
            block(d, detail, x + 34, 564, font(33), 477, fill=MUTED)
        d.text((89, 787), "uv installation: docs.astral.sh/uv/getting-started/installation", font=font(28), fill=GREEN)
    elif kind == "terminal":
        box(d, (80, 305, 1400, 850), fill="#0b1c24")
        for i, color in enumerate(["#ff6f78", "#f5c56a", GREEN]):
            d.ellipse((106 + i * 27, 330, 120 + i * 27, 344), fill=color)
        d.text((215, 324), "TERMINAL  ·  COPY THESE COMMANDS", font=font(20, bold=True), fill=MUTED)
        box(d, (1430, 305, 1840, 850))
        d.text((1460, 342), "REMEMBER", font=font(22, bold=True), fill=GREEN)
        block(d, scene.get("tip", ""), 1460, 401, font(29), 345, gap=16)
    elif kind == "agent":
        agent = scene["agent"]
        report = evidence["agents"][agent]
        color = GREEN if agent == "codex" else PURPLE
        box(d, (80, 306, 1840, 850))
        d.text((115, 338), "PROMPT TO COPY", font=font(23, bold=True), fill=color)
        block(d, scene["prompt"], 116, 393, font(38), 1650, gap=13)
        d.line((116, 584, 1805, 584), fill=LINE, width=2)
        d.text((116, 620), "ANSWER FROM " + agent.upper(), font=font(23, bold=True), fill=color)
        for i, result in enumerate(report["highlights"]):
            x = 116 + i * 840
            d.text((x, 684), result["name"], font=font(35, bold=True), fill=INK)
            d.text((x, 738), result["price"], font=font(42), fill=color)
        d.text((116, 809), "Task completed  ·  shopping account", font=font(24), fill=MUTED)
    elif kind == "ui":
        box(d, (1400, 306, 1840, 850))
        d.text((1430, 346), "ACCOUNT SETUP", font=font(23, bold=True), fill=GREEN)
        block(d, scene["tip"], 1430, 412, font(28), 374, gap=15)
    elif kind == "owner":
        shot = Image.open(OUT / "assets/owner-password.png").convert("RGB")
        scale = min(1260 / shot.width, 510 / shot.height)
        shot = shot.resize((round(shot.width * scale), round(shot.height * scale)), Image.Resampling.LANCZOS)
        image.paste(shot, (80, 315))
        box(d, (1400, 306, 1840, 850))
        d.text((1433, 347), "OWNER SETUP", font=font(24, bold=True), fill=GREEN)
        y = 402
        for title, desc in [("Save locally", "Enter email and password once."), ("Allow operations", "Choose what each agent can read."), ("Revoke access", "Stop future service access.")]:
            d.text((1433, y), title, font=font(28, bold=True), fill=INK)
            y = block(d, desc, 1433, y + 43, font(24), 368, fill=MUTED, gap=8) + 28
        d.text((83, 845), "Captured from the actual local owner console. No saved password is displayed.", font=font(21), fill=MUTED)
    elif kind == "authentication":
        rows = [
            ("Password", "Enter once in local setup", "Implemented"),
            ("Authenticator TOTP", "Explicitly enroll a login secret", "Demo-tested"),
            ("Email / SMS", "Configured Gmail / Twilio sources", "Live testing pending"),
            ("Password-manager import", "Chrome / other saved passwords", "Not built yet"),
            ("Personal phone SMS", "Your existing iPhone / Android inbox", "Not built yet"),
        ]
        for i, (title, desc, state) in enumerate(rows):
            y = 306 + i * 106
            box(d, (80, y, 1840, y + 92), radius=16)
            d.text((108, y + 28), title, font=font(29, bold=True), fill=INK)
            d.text((610, y + 30), desc, font=font(28), fill=MUTED)
            d.text((1490, y + 30), state, font=font(25, bold=True), fill=GREEN if i < 2 else "#f0c782")
    elif kind == "statuses":
        statuses = [
            ("Skill missing", "Open a fresh agent chat or session."),
            ("service_unavailable", "Start the service. Keep its terminal open."),
            ("NEEDS_USER", "Complete owner setup. Continue the same task."),
            ("DENIED", "Review the account's granted permissions."),
        ]
        for i, (title, desc) in enumerate(statuses):
            y = 315 + i * 128
            box(d, (80, y, 1840, y + 107), radius=16)
            d.text((110, y + 30), title, font=font(32, bold=True), fill=GREEN)
            d.text((656, y + 33), desc, font=font(31), fill=INK)
    return image


def terminal_overlay(frame, scene, t):
    d = ImageDraw.Draw(frame)
    face = font(28, mono=True)
    command = scene["command"]
    shown = command[:min(len(command), int(t * 110))]
    y = 385
    for line in shown.split("\n"):
        d.text((110, y), ("$ " if line and not line.startswith(" ") else "  ") + line, font=face, fill=GREEN)
        y += 40
    if t >= len(command) / 110 + 0.7:
        y = 385 + len(command.split("\n")) * 40 + 30
        for line in scene["output"].split("\n"):
            if y + 30 > 840:
                raise RuntimeError(f"Terminal content exceeds panel: {scene['id']}")
            d.text((111, y), line, font=face, fill=INK)
            y += 37


def ui_overlay(frame, scene, t):
    fraction = min(0.99, t / scene["duration"])
    index = min(len(scene["assets"]) - 1, int(fraction * len(scene["assets"])))
    shot = Image.open(OUT / "assets" / scene["assets"][index]).convert("RGB")
    scale = min(1260 / shot.width, 510 / shot.height)
    shot = shot.resize((round(shot.width * scale), round(shot.height * scale)), Image.Resampling.LANCZOS)
    frame.paste(shot, (80, 315))
    label_index = min(len(scene["labels"]) - 1, int(fraction * len(scene["labels"])))
    d = ImageDraw.Draw(frame)
    d.text((82, 846), scene["labels"][label_index], font=font(23, bold=True), fill=GREEN)


def render(scenes, evidence, total):
    output = OUT / "account-access-walkthrough.mp4"
    command = [
        "ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-f", "rawvideo",
        "-pixel_format", "rgb24", "-video_size", f"{W}x{H}", "-framerate", str(FPS), "-i", "pipe:0",
        "-i", str(OUT / "narration.wav"), "-c:v", "libx264", "-preset", "veryfast", "-crf", "20",
        "-pix_fmt", "yuv420p", "-r", "24", "-c:a", "aac", "-b:a", "128k",
        "-movflags", "+faststart", "-shortest", str(output),
    ]
    previews = OUT / "work/previews"
    previews.mkdir(exist_ok=True)
    encoder = subprocess.Popen(command, stdin=subprocess.PIPE)
    try:
        for n, scene in enumerate(scenes):
            base = base_frame(scene, n, evidence)
            cache = {}
            for j in range(round(scene["duration"] * FPS)):
                t = j / FPS
                text = next((x["text"] for x in scene["captions"] if x["start"] <= t < x["end"]), "")
                if text not in cache:
                    captioned = base.copy()
                    d = ImageDraw.Draw(captioned)
                    lines = wrap(text, font(31), 1690)
                    if len(lines) > 2:
                        raise RuntimeError(f"Caption exceeds two lines: {text}")
                    for i, line in enumerate(lines):
                        width = font(31).getlength(line)
                        d.text(((W - width) / 2, 906 + 42 * i), line, font=font(31), fill=INK)
                    cache[text] = captioned
                frame = cache[text].copy()
                if scene["kind"] == "terminal":
                    terminal_overlay(frame, scene, t)
                elif scene["kind"] == "ui":
                    ui_overlay(frame, scene, t)
                d = ImageDraw.Draw(frame)
                progress = (scene["start"] + t) / total
                d.rectangle((0, H - 5, round(W * progress), H), fill=GREEN)
                if t < 0.28:
                    alpha = max(0, 1 - t / 0.28)
                    frame = Image.blend(frame, Image.new("RGB", (W, H), "#08171f"), alpha)
                if j == round(scene["duration"] * FPS / 2):
                    frame.save(previews / f"{n:02}-{scene['id']}.png")
                    if scene["id"] == "intro":
                        poster = base.copy()
                        poster.thumbnail((1280, 720))
                        poster.save(ROOT / "docs/video/poster.jpg", quality=92)
                encoder.stdin.write(frame.tobytes())
            print(f"Rendered {n + 1}/{len(scenes)}: {scene['title']}", flush=True)
        encoder.stdin.close()
        if encoder.wait() != 0:
            raise RuntimeError("Video encoder failed")
    except BaseException:
        encoder.kill()
        raise
    return output


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--voice", default="Samantha")
    args = p.parse_args()
    for program in ["say", "ffmpeg", "ffprobe"]:
        if not shutil.which(program):
            raise SystemExit(f"Required local program missing: {program}")
    WORK.mkdir(parents=True, exist_ok=True)
    scenes = json.loads((ROOT / "docs/video/storyboard.json").read_text())
    evidence = json.loads((OUT / "evidence.json").read_text())
    for agent in ["codex", "claude"]:
        if not evidence["agents"][agent]["passed"]:
            raise SystemExit(f"Verified successful account read required: {agent}")
    total = prepare_audio(scenes, args.voice)
    video = render(scenes, evidence, total)
    print(json.dumps({"file": video.name, "duration_seconds": round(total, 3), "bytes": video.stat().st_size}))


if __name__ == "__main__":
    main()
