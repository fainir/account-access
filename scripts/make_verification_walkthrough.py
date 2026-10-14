"""Edit actual 0.5 installation, owner setup, Claude Code and browser recordings.

Application pixels come only from video captures. Pillow supplies caption bars.
Private source footage and receipts are required and remain outside Git.
"""

import argparse
import json
import textwrap
from pathlib import Path

from make_full_walkthrough import duration, run, strip


def timestamp(seconds):
    milliseconds = round(seconds * 1000)
    hours, milliseconds = divmod(milliseconds, 3_600_000)
    minutes, milliseconds = divmod(milliseconds, 60_000)
    seconds, milliseconds = divmod(milliseconds, 1000)
    return f"{hours:02}:{minutes:02}:{seconds:02}.{milliseconds:03}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    work = args.work.resolve()
    render = work / "render05"
    render.mkdir(exist_ok=True)
    proof = json.loads((work / "proof.json").read_text())
    for key in ("claude_task", "codex_task"):
        assert proof[key]["status"] == "COMPLETED"
        assert proof[key]["progress"] == proof[key]["total"] == 4
    assert proof["user_login_inputs_during_recorded_claude_task"] == 0
    logins = {row["account"]: work / row["source"] for row in proof["recorded_logins"]}
    native = "iw:ih:0:0"
    scenes = [
        ("install-import.mov", 0, 12, 1.5, "1 · Open Account Access and click Install",
         "Graphical Mac preview · Four configured example accounts in this walkthrough",
         "Open Account Access and click Install. The app prepares the software and browser for you.", native),
        ("install-import.mov", 98, 116, 2.0, "The portable skill is installed automatically",
         "One skill + CLI · Claude Code and Codex detected · Installation wait shortened",
         "Your existing AI tools are detected automatically. The same portable skill works through a command-line client. You don't choose an agent during setup.", native),
        ("email-setup.mov", 12, 23, 1, "2 · Connect the verification sources once",
         "Email example uses TLS IMAP · Configure the supported mailbox locally",
         "Connect your configured email mailbox once, using its email address and application password. This example mailbox uses encrypted IMAP.", native),
        ("sms-setup.mov", 16, 24, 1, "Set up SMS verification",
         "iPhone: Messages forwarding + Mac permission · Android: pair the companion",
         "For iPhone, forward texts to Messages and allow the Account Access app in Mac privacy settings. Android users pair the phone companion instead.", native),
        ("import-review.mov", 0, 12, 1, "3 · Review and import your saved passwords",
         "Supported CSV export · Approve account reads · Authenticator keys require opt-in",
         "Choose a password export from Chrome or another supported manager. Review the matched accounts and approve their reads. Import authenticator keys only if you choose that option.", native),
        ("ready-open-claude.mov", 0, 10, 1, "4 · Copy the request and open Claude Code",
         "Four accounts connected · Password, authenticator, email and SMS",
         "When your accounts are connected, copy the request and open Claude Code. You can use the same skill from Codex or another compatible local agent.", native),
        ("claude-four-accounts.mov", 0.2, 6, 1, "5 · Ask Claude Code for the work",
         "Actual Claude Code interface · One request for all four permitted reads",
         "Ask Claude to read your connected accounts and save progress as one task.", "1680:330:112:1830"),
        ("claude-four-accounts.mov", 10, 33, 2, "Claude Code starts one saved account task",
         "Actual request · Saved example sessions expired to show fresh sign-ins",
         "Claude discovers the permitted accounts and starts the task. We expired the example sessions so you can watch each fresh sign-in.", "1680:950:112:76"),
    ]
    examples = [
        ("demo-web", "Password sign-in", "Saved username and masked password · No user input",
         "Account Access fills the saved username and password and signs in automatically."),
        ("demo-mfa", "Authenticator verification", "Enrolled TOTP key · Six-digit login code generated locally",
         "For the authenticator account, it generates the login code from the explicitly imported setup key and submits it. You don't open the authenticator app."),
        ("example-email", "Email verification", "Fresh code read over TLS IMAP · Synthetic mailbox delivery",
         "For email verification, it reads the fresh matching message from the connected mailbox and submits the code. You don't copy it."),
        ("example-sms", "SMS verification", "Fresh matching login message · Messages-format fixture in this recording",
         "For SMS, it retrieves the matching fresh login message and submits the code. This recording uses a controlled Messages fixture; real phone delivery still needs validation."),
    ]
    for account, title, caption, narration in examples:
        source = logins[account]
        scenes.append((source.name, 0, duration(source), .32, title, caption, narration, "800:450:0:0"))
    scenes.append(("claude-four-accounts.mov", 120, 135, 1,
                   "6 · Claude Code returns all four results",
                   "One task completed · Four account reads · No further password or code entry",
                   "Claude returns all four results and the saved task ID. From the request through completion, the user entered no password or verification code. These are configured example accounts; private websites need reviewed connectors.",
                   "1640:960:132:436"))
    segments, timeline = [], []
    elapsed = 0.0
    for index, (name, start, end, speed, title, caption, narration, crop) in enumerate(scenes):
        source = work / name
        assert source.is_file() and duration(source) > start
        top, bottom = render / f"title-{index}.png", render / f"caption-{index}.png"
        strip(top, title)
        strip(bottom, caption)
        voice_text, voice = render / f"voice-{index}.txt", render / f"voice-{index}.aiff"
        voice_text.write_text(narration)
        run(["say", "-v", "Samantha", "-r", "155", "-f", str(voice_text), "-o", str(voice)])
        end = min(end, duration(source))
        base = (end - start) / speed
        hold = max(.7, duration(voice) + .7 - base)
        transform = f"trim=start={start}:end={end},setpts=(PTS-STARTPTS)/{speed},crop={crop},tpad=stop_mode=clone:stop_duration={hold}"
        filters = (
            f"[0:v]{transform},fps=24,scale=1920:920:force_original_aspect_ratio=decrease:force_divisible_by=2,"
            "setsar=1,pad=1920:1080:(ow-iw)/2:80:color=0x111318[body];"
            "[body][2:v]overlay=0:0:shortest=1[title];[title][3:v]overlay=0:1000:shortest=1[v];"
            "[1:a]aresample=48000,apad[a]"
        )
        segment = render / f"scene-{index}.mp4"
        run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-i", str(source), "-i", str(voice),
             "-loop", "1", "-i", str(top), "-loop", "1", "-i", str(bottom), "-filter_complex_threads", "1",
             "-filter_complex", filters, "-map", "[v]", "-map", "[a]", "-c:v", "libx264", "-threads", "2",
             "-preset", "veryfast", "-crf", "19", "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "160k",
             "-ac", "2", "-shortest", str(segment)])
        seconds = duration(segment)
        timeline.append({"start": elapsed, "end": elapsed + seconds, "title": title, "narration": narration,
                         "source": source.name, "source_start": start, "source_end": end, "speed": speed})
        elapsed += seconds
        segments.append(segment)
        print(f"Rendered {index + 1}/{len(scenes)}: {title}", flush=True)
    concat = render / "concat.txt"
    concat.write_text("".join("file '" + str(path).replace("'", "'\\''") + "'\n" for path in segments))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-f", "concat", "-safe", "0", "-i", str(concat),
         "-c", "copy", "-movflags", "+faststart", str(args.output)])
    (work / "timeline05.json").write_text(json.dumps(timeline, indent=2))
    captions = ["WEBVTT\n"]
    for scene in timeline:
        captions.append(timestamp(scene["start"]) + " --> " + timestamp(scene["end"]) + "\n" +
                        "\n".join(textwrap.wrap(scene["narration"], 80)) + "\n")
    args.output.with_suffix(".vtt").write_text("\n".join(captions))
    print(args.output.resolve())


if __name__ == "__main__":
    main()
