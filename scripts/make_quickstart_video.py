"""Edit the 0.6 computer captures into a short, narrated walkthrough.

Requires ffmpeg, macOS `say`, Pillow, and the private source captures. Pillow
draws caption strips only; application and website pixels are recorded footage.
"""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


def run(args):
    subprocess.run(args, check=True)


def duration(path):
    data = subprocess.check_output([
        "ffprobe", "-v", "error", "-show_entries", "format=duration",
        "-of", "json", str(path),
    ], text=True)
    return float(json.loads(data)["format"]["duration"])


def caption(path, title):
    image = Image.new("RGBA", (1920, 1080), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    font_path = "/System/Library/Fonts/Supplemental/Arial.ttf"
    title_font = ImageFont.truetype(font_path, 32)
    small_font = ImageFont.truetype(font_path, 23)
    draw.rectangle((0, 0, 1920, 61), fill="#191b22")
    draw.text((48, 13), title, font=title_font, fill="white")
    draw.rectangle((0, 1044, 1920, 1080), fill="#191b22")
    note = "Example accounts · Test email/SMS delivery · Waiting periods shortened"
    draw.text((48, 1049), note, font=small_font, fill="#c4c7d2")
    image.save(path)


def timestamp(seconds):
    milliseconds = round(seconds * 1000)
    hours, milliseconds = divmod(milliseconds, 3600000)
    minutes, milliseconds = divmod(milliseconds, 60000)
    seconds, milliseconds = divmod(milliseconds, 1000)
    return f"{hours:02}:{minutes:02}:{seconds:02}.{milliseconds:03}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    render = work / "quick-render"
    render.mkdir(exist_ok=True)
    proof = json.loads((work / "proof.json").read_text())
    task = json.loads((work / "task.json").read_text())
    assert task["status"] == "COMPLETED" and task["progress"] == task["total"] == 4
    assert proof["user_requests"] == 1
    assert proof["user_password_or_code_inputs_after_request"] == 0
    assert proof["explicit_skill_or_command_in_prompt"] is False
    logins = {}
    for row in proof["recorded_logins"]:
        source = work / row["source"]
        assert hashlib.sha256(source.read_bytes()).hexdigest() == row["sha256"]
        logins[row["account"]] = source.name
    assert set(logins) == {"demo-web", "demo-mfa", "example-email", "example-sms"}

    # Each cut is (source, source start, source end, playback seconds, crop).
    groups = [
        ("1 · Download and open Account Access",
         "Download Account Access for Mac, then open the app.", [
             ("download-clean.mov", 3, 8, 5, "1320:660:280:350"),
             ("open-app.mov", 7.8, 12, 2, "860:410:0:0"),
         ]),
        ("1 · Click Install · Your AI tools connect automatically",
         "Click Install. Your existing AI tools are connected automatically.", [
             ("install-clean.mov", 0, 5, 2, None),
             ("install-clean.mov", 9, 31, 3, None),
             ("install-clean.mov", 32, 34, 1, None),
         ]),
        ("2 · Import from Chrome or your password manager",
         "Choose your password export from Chrome or a password manager. Approve what your AI can read.", [
             ("setup.mov", 3, 8, 2, None),
             ("import-picker.mov", 6, 13.8, 2.5, None),
             ("email-final.mov", 79, 91, 5, None),
         ]),
        ("3 · Connect email once",
         "Connect your email once, using its application password.", [
             ("email-final.mov", 0, 10.5, 6, None),
         ]),
        ("3 · Set up SMS forwarding and Mac access",
         "For SMS, set up forwarding to Messages and the Mac permission.", [
             ("sms-retake.mov", 12, 26, 5.5, None),
         ]),
        ("3 · Add your authenticator setup QR or key",
         "Add your authenticator's setup QR or key once.", [
             ("auth-final.mov", 0, 4, 1, None),
             ("auth-picker.mov", 0, 14.8, 2.5, None),
             ("auth-final.mov", 41, 51, 3, None),
         ]),
        ("4 · Ask Claude Code normally · No command needed",
         "In Claude Code, just ask normally. No command or skill name.", [
             ("claude-request.mov", 7.5, 15.5, 6, "900:145:0:155"),
             ("claude-working.mov", 0, 3, 2, None),
         ]),
        ("5 · Atlas Membership · Saved password",
         "The saved password signs into Atlas.", [
             (logins["demo-web"], 0.08, 2.5, 4.5, None),
         ]),
        ("5 · Juniper Workspace · Authenticator code",
         "The authenticator code is generated and submitted.", [
             (logins["demo-mfa"], 0.08, 2.8, 5.5, None),
         ]),
        ("5 · Beacon Rewards · Email code",
         "The email code is retrieved and entered.", [
             (logins["example-email"], 0.08, 3.3, 5.5, None),
         ]),
        ("5 · Orbit Travel · SMS code",
         "The SMS code is retrieved and entered.", [
             (logins["example-sms"], 0.08, 3.5, 5.5, None),
         ]),
        ("All four results · One request",
         "Claude returns all four results. No more password or code entry during this task.", [
             ("claude-working.mov", 10, 15.5, 5.5, None),
         ]),
    ]
    segments, timeline, narration, cursor = [], [], [], 0.0
    for index, (title, words, cuts) in enumerate(groups):
        overlay = render / f"caption-{index}.png"
        caption(overlay, title)
        clips = []
        group_seconds = sum(cut[3] for cut in cuts)
        for number, (filename, start, end, seconds, crop) in enumerate(cuts):
            source = work / filename
            assert source.is_file() and end <= duration(source) + 0.05, filename
            rate = (end - start) / seconds
            transform = f"setpts=(PTS-STARTPTS)/{rate}"
            if crop:
                transform += ",crop=" + crop
            filters = (
                f"[0:v]{transform},fps=30,"
                "scale=1920:982:force_original_aspect_ratio=decrease:force_divisible_by=2,"
                "setsar=1,pad=1920:1080:(ow-iw)/2:61+(982-ih)/2:color=0x191b22,"
                "tpad=stop_mode=clone:stop_duration=1[body];"
                "[body][1:v]overlay=0:0:shortest=1,format=yuv420p[v]"
            )
            clip = render / f"clip-{index}-{number}.mp4"
            run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
                 "-filter_complex_threads", "1", "-ss", str(start), "-t", str(end-start),
                 "-i", str(source), "-loop", "1", "-i", str(overlay),
                 "-filter_complex", filters, "-map", "[v]", "-an", "-t", str(seconds),
                 "-c:v", "libx264", "-threads", "2", "-preset", "fast", "-crf", "19",
                 "-video_track_timescale", "30000", str(clip)])
            clips.append(clip)
        listing = render / f"clips-{index}.txt"
        listing.write_text("".join(f"file '{clip.name}'\n" for clip in clips))
        joined = render / f"joined-{index}.mp4"
        run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-f", "concat",
             "-safe", "0", "-i", str(listing), "-c", "copy", str(joined)])
        voice_text = render / f"voice-{index}.txt"
        voice = render / f"voice-{index}.aiff"
        voice_text.write_text(words)
        run(["say", "-v", "Samantha", "-r", "185", "-f", str(voice_text), "-o", str(voice)])
        voice_seconds = duration(voice)
        assert voice_seconds < group_seconds, (title, voice_seconds, group_seconds)
        segment = render / f"scene-{index}.mp4"
        run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-i", str(joined),
             "-i", str(voice), "-map", "0:v", "-map", "1:a", "-c:v", "copy",
             "-af", "adelay=160|160,apad", "-c:a", "aac", "-b:a", "160k", "-ar", "48000",
             "-ac", "2", "-t", str(group_seconds), str(segment)])
        timeline.append({"start": cursor, "end": cursor + group_seconds, "title": title,
                         "narration": words, "cuts": [dict(source=c[0], start=c[1], end=c[2],
                         seconds=c[3], crop=c[4]) for c in cuts]})
        narration.append(f"{timestamp(cursor + .16)} --> {timestamp(cursor + .16 + voice_seconds)}\n{words}\n")
        cursor += group_seconds
        segments.append(segment)
        print(f"Rendered {index+1}/{len(groups)}: {title}", flush=True)
    assert cursor <= 80, cursor
    listing = render / "scenes.txt"
    listing.write_text("".join(f"file '{segment.name}'\n" for segment in segments))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-f", "concat", "-safe", "0",
         "-i", str(listing), "-c", "copy", "-movflags", "+faststart", str(args.output)])
    args.output.with_suffix(".vtt").write_text("WEBVTT\n\n" + "\n".join(narration))
    (work / "quick-timeline.json").write_text(json.dumps(timeline, indent=2))
    print(f"Saved {args.output.resolve()} ({duration(args.output):.2f}s)")


if __name__ == "__main__":
    main()
