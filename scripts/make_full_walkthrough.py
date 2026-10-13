"""Edit recorded Finder, native app, Claude Code and actual login page footage.

Pillow creates caption strips only. Every application/page pixel comes from a
recorded video. A completed three-account task and three login receipts are
required before this script exports the complete walkthrough.
"""

import argparse
import json
import subprocess
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


def run(args):
    subprocess.run(args, check=True)


def duration(path):
    data = subprocess.check_output([
        "ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "json", str(path)
    ], text=True)
    return float(json.loads(data)["format"]["duration"])


def strip(path, text):
    canvas = Image.new("RGB", (1920, 80), "#111318")
    draw = ImageDraw.Draw(canvas)
    face = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial.ttf", 31)
    draw.text(((1920 - face.getlength(text)) / 2, 21), text, font=face, fill="white")
    canvas.save(path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    render = work / "render"
    render.mkdir(exist_ok=True)
    proof = json.loads((work / "proof.json").read_text())
    task = json.loads((work / "task.json").read_text())
    assert task["status"] == "COMPLETED" and task["progress"] == task["total"] == 3
    assert proof["user_requests"] == 1 and proof["user_login_inputs_during_task"] == 0
    assert len(proof["logins"]) == 3
    expected = {"personal-store", "work-store", "member-portal"}
    assert {item["account"] for item in proof["logins"]} == expected
    manifest = json.loads((work / "manifest.json").read_text())
    logins = {item["account"]: Path(item["video"]) for item in manifest["records"]
              if item["phase"] == "login" and item["closed_at"]}
    assert set(logins) == expected and all(path.stat().st_size for path in logins.values())
    setup = work / "install-and-connect.mov"
    scenes = [
        (work / "open-installer.mov", 0, 3, 1, "Open Account Access on your Mac",
         "Actual computer recording · Graphical Mac preview · Three example accounts",
         "Open Account Access on your Mac.", None),
        (setup, 0, 32, 2.4, "1 · Install Account Access",
         "Click Install · The app prepares the software · Waiting time shortened",
         "Click Install. Account Access prepares the software for you. Wait until the setup screen opens.", "1760:1030:112:76"),
        (setup, 66, 77, 1, "2 · Choose your existing AI tools",
         "Select Claude Code, Codex, or both · Click Set up my AI tools",
         "Choose Claude Code, Codex, or both. Then click Set up my AI tools. The app adds the Account Access skill for you.", "1760:1030:112:76"),
        (setup, 77, 88, 1, "3 · Connect your personal account once",
         "Enter the login once · Approve the permitted read · Click Connect account",
         "Choose an account. Enter its username or email and password once. Approve what your AI can read, then click Connect account.", "1760:1120:112:76"),
        (setup, 88, 100, 1, "Connect your work account",
         "Each account has its own saved login and approved read",
         "Repeat for the work account, using its separate login. Approve the product read and connect it.", "1760:1120:112:76"),
        (setup, 100, 116, 1.2, "Connect your membership account",
         "Approve the welcome-message read · All three accounts become connected",
         "Add the membership account and approve its welcome message read. When all three accounts turn green, you're ready.", "1760:1120:112:76"),
        (setup, 116, 149, 3.1, "4 · Copy the request and open Claude Code",
         "Accounts connected once · Copy request → Open Claude Code",
         "You won't retype these passwords during the task. Copy the request and open Claude Code.", "1760:1120:112:76"),
        (work / "claude-working.mov", 0, 5, 1, "5 · Ask Claude Code to do the work",
         "The sent request is visible in the actual Claude Code app",
         "In a fresh Claude Code chat, ask for the work. One request starts all three account reads.", "1680:950:112:76"),
        (work / "claude-working.mov", 5, 16, 1, "Claude Code starts the account task",
         "The example sessions were expired so fresh automatic logins are visible",
         "Claude discovers the permitted accounts and starts one task. The example sessions were expired, so you can watch fresh sign-ins.", "1680:950:112:76"),
    ]
    for account, label, narration in [
        ("personal-store", "Personal shopping account",
         "The first shopping account opens. Account Access fills the saved username and masked password, then signs in. The user leaves the login form alone."),
        ("work-store", "Work shopping account",
         "Next, it signs into the work account automatically, using its separate saved login. It then reads product names and prices."),
        ("member-portal", "Membership account",
         "Then it signs into the membership account and reads the welcome message. No password entry or login clicks are needed from the user."),
    ]:
        scenes.append((logins[account], 0, duration(logins[account]), 1 / 3,
                       "Account Access signs in · " + label,
                       "Actual browser activity · Login playback slowed to show the steps",
                       narration, "800:450:0:0" if account == "member-portal" else None))
    scenes.append((work / "claude-result.mov", 0, 11.9, 1,
                   "6 · Claude Code returns the completed results",
                   "Three reads completed · One request · No further login input",
                   "Claude shows the results from all three accounts. Both shopping accounts have the same cheapest product at seven dollars and ninety-nine cents. The membership welcome message is included, and the task is saved.",
                   "1680:1100:112:76"))
    segments = []
    timeline = []
    start_at = 0.0
    for index, (source, start, end, speed, title, caption, narration, crop) in enumerate(scenes):
        assert source.is_file()
        top, bottom = render / f"title-{index}.png", render / f"caption-{index}.png"
        strip(top, title)
        strip(bottom, caption)
        voice_text, voice = render / f"voice-{index}.txt", render / f"voice-{index}.aiff"
        voice_text.write_text(narration)
        run(["say", "-v", "Samantha", "-r", "148", "-f", str(voice_text), "-o", str(voice)])
        end = min(end, duration(source))
        base_duration = (end - start) / speed
        hold = max(0.7, duration(voice) + 0.7 - base_duration)
        transform = f"trim=start={start}:end={end},setpts=(PTS-STARTPTS)/{speed}"
        if crop:
            transform += ",crop=" + crop
        transform += f",tpad=stop_mode=clone:stop_duration={hold}"
        filters = (
            f"[0:v]{transform},fps=30,"
            "scale=1920:920:force_original_aspect_ratio=decrease:force_divisible_by=2:out_color_matrix=bt709:out_range=tv,"
            "setsar=1,pad=1920:1080:(ow-iw)/2:80:color=0x111318[body];"
            "[body][2:v]overlay=0:0:shortest=1[title];"
            "[title][3:v]overlay=0:1000:shortest=1[v];"
            "[1:a]aresample=48000,apad[a]"
        )
        segment = render / f"scene-{index}.mp4"
        run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-i", str(source),
             "-i", str(voice), "-loop", "1", "-i", str(top), "-loop", "1", "-i", str(bottom),
             "-filter_complex", filters, "-map", "[v]", "-map", "[a]", "-c:v", "libx264",
             "-preset", "fast", "-crf", "19", "-pix_fmt", "yuv420p", "-color_primaries", "bt709",
             "-color_trc", "bt709", "-colorspace", "bt709", "-color_range", "tv", "-c:a", "aac",
             "-b:a", "160k", "-ac", "2", "-shortest", str(segment)])
        seconds = duration(segment)
        timeline.append({"start": start_at, "end": start_at + seconds, "title": title,
                         "narration": narration, "source": source.name, "source_start": start,
                         "source_end": end, "speed": speed})
        start_at += seconds
        segments.append(segment)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    inputs, filters, order = [], [], ""
    for index, segment in enumerate(segments):
        inputs += ["-i", str(segment)]
        filters.append(f"[{index}:v]setpts=PTS-STARTPTS,setsar=1[v{index}];"
                       f"[{index}:a]asetpts=PTS-STARTPTS[a{index}]")
        order += f"[v{index}][a{index}]"
    filters.append(order + f"concat=n={len(segments)}:v=1:a=1[v][a]")
    run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", *inputs,
         "-filter_complex", ";".join(filters), "-map", "[v]", "-map", "[a]",
         "-c:v", "libx264", "-preset", "fast", "-crf", "19", "-pix_fmt", "yuv420p",
         "-color_primaries", "bt709", "-color_trc", "bt709", "-colorspace", "bt709",
         "-color_range", "tv", "-c:a", "aac", "-b:a", "160k", "-ac", "2",
         "-movflags", "+faststart", str(args.output)])
    (work / "timeline.json").write_text(json.dumps(timeline, indent=2))
    print(args.output.resolve())


if __name__ == "__main__":
    main()
