"""
Automated Headless Demo Video Generator for Otari-Sentry.
Generates:
1. Neural narration audio with edge-tts (voice: en-US-ChristopherNeural).
2. Headless 1080p Playwright Chromium screen interaction synchronized to audio beats.
3. High-definition MP4 export (H.264/AAC) via FFmpeg: otari_sentry_demo.mp4.
"""

import asyncio
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import edge_tts
import imageio_ffmpeg
from moviepy import AudioFileClip

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
TEMP_DIR = SCRIPTS_DIR / "temp_artifacts"
RECORDING_DIR = SCRIPTS_DIR / "temp_recording"
DEMO_AUDIO_PATH = SCRIPTS_DIR / "demo_audio.mp3"
FINAL_VIDEO_PATH = PROJECT_ROOT / "otari_sentry_demo.mp4"
BASE_URL = "http://127.0.0.1:8000"

VOICE = "en-US-ChristopherNeural"

# Structured Enterprise Architect Script Beats
NARRATION_BEATS = [
    {
        "id": "beat_1_overview",
        "title": "Architecture & Gateway Overview",
        "text": (
            "Welcome to Otari-Sentry, the enterprise AI security gateway and deterministic policy "
            "enforcement firewall protecting Mozilla Otari Hosted AI Gateway. "
            "Our foundational philosophy: Rules Engine Decides, AI Explains."
        ),
    },
    {
        "id": "beat_2_jailbreak",
        "title": "Airlock Zero-Token Rejection",
        "text": (
            "We first test our deterministic ingress airlock with a prompt jailbreak attack. "
            "In under zero point one milliseconds, the compile-time regex engine intercepts the threat, "
            "terminating the request with HTTP 403 Forbidden and zero LLM tokens burned."
        ),
    },
    {
        "id": "beat_3_valid",
        "title": "Admitted Inference via Mozilla Otari",
        "text": (
            "Next, a valid system query passes inspection and routes dynamically to Mozilla Otari "
            "with resilient SLA timeout fallback, streaming verified completion tokens from Qwen thirty-five B."
        ),
    },
    {
        "id": "beat_4_cache",
        "title": "Sub-Millisecond Semantic Cache & USD Savings",
        "text": (
            "Now, an identical semantic cache replay returns in just zero point zero zero five milliseconds. "
            "Zero new upstream tokens are consumed, while the ledger records live USD cost savings."
        ),
    },
    {
        "id": "beat_5_outro",
        "title": "Enterprise Reliability & Governance",
        "text": (
            "With deterministic guardrails, native sandbox code execution, and real-time financial telemetry, "
            "Otari-Sentry delivers production-grade reliability and cost governance for enterprise AI."
        ),
    },
]


def log(msg: str):
    print(f"[Otari-Sentry Demo Pipeline] {msg}", flush=True)


async def generate_neural_audio():
    """
    Step A: Generate neural audio clips for each narration beat and merge into demo_audio.mp3.
    """
    log("=== STEP A: Neural Audio Generation (edge-tts) ===")
    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    audio_files = []
    beat_durations = {}

    for i, beat in enumerate(NARRATION_BEATS):
        beat_id = beat["id"]
        out_file = TEMP_DIR / f"{beat_id}.mp3"
        log(f"Generating voiceover: {beat['title']}...")
        communicate = edge_tts.Communicate(beat["text"], VOICE)
        await communicate.save(str(out_file))

        clip = AudioFileClip(str(out_file))
        duration = clip.duration
        clip.close()
        beat_durations[beat_id] = duration
        audio_files.append(out_file)
        log(f"  -> Beat {i+1} duration: {duration:.2f}s")

    # Combine into single demo_audio.mp3 using ffmpeg
    ffmpeg_exe = imageio_ffmpeg.get_ffmpeg_exe()
    concat_list_file = TEMP_DIR / "concat_list.txt"
    with open(concat_list_file, "w", encoding="utf-8") as f:
        for af in audio_files:
            # Escape path for ffmpeg concat
            clean_path = str(af).replace("\\", "/")
            f.write(f"file '{clean_path}'\n")

    log("Merging audio tracks into demo_audio.mp3...")
    merge_cmd = [
        ffmpeg_exe,
        "-y",
        "-f", "concat",
        "-safe", "0",
        "-i", str(concat_list_file),
        "-c", "copy",
        str(DEMO_AUDIO_PATH),
    ]
    subprocess.run(merge_cmd, check=True, capture_output=True)

    total_clip = AudioFileClip(str(DEMO_AUDIO_PATH))
    total_duration = total_clip.duration
    total_clip.close()
    log(f"Complete audio track ready: {DEMO_AUDIO_PATH} ({total_duration:.2f}s)")
    return beat_durations, total_duration


async def record_browser_interaction(beat_durations: dict):
    """
    Step B: Automated 1080p Headless Browser Interaction & Screen Recording.
    Synchronized with each narration beat.
    """
    log("=== STEP B: Headless Browser Interaction & Recording (Playwright) ===")
    from playwright.async_api import async_playwright

    RECORDING_DIR.mkdir(parents=True, exist_ok=True)

    async with async_playwright() as p:
        log("Launching Playwright Chromium (1920x1080 viewport)...")
        browser = await p.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--hide-scrollbars",
            ],
        )
        context = await browser.new_context(
            viewport={"width": 1920, "height": 1080},
            record_video_dir=str(RECORDING_DIR),
            record_video_size={"width": 1920, "height": 1080},
        )
        page = await context.new_page()

        log(f"Navigating to Otari-Sentry Dashboard ({BASE_URL})...")
        await page.goto(BASE_URL, wait_until="networkidle")
        await page.wait_for_selector("#gateway-status")

        # ----------------------------------------------------------------------
        # Beat 1: Architecture & Clean Dashboard Overview
        # ----------------------------------------------------------------------
        b1_duration = beat_durations["beat_1_overview"]
        log(f"Beat 1: Overview and live infrastructure status ({b1_duration:.2f}s)...")
        t0 = time.perf_counter()
        # Visual mouse hover on top status badges
        await page.hover("#gateway-status")
        await asyncio.sleep(1.5)
        await page.hover("#target-model-badge")
        await asyncio.sleep(1.5)
        await page.hover("#circuit-state-badge")
        await asyncio.sleep(1.5)
        elapsed_b1 = time.perf_counter() - t0
        if elapsed_b1 < b1_duration:
            await asyncio.sleep(b1_duration - elapsed_b1)

        # ----------------------------------------------------------------------
        # Beat 2: Jailbreak Attack & Sub-0.1ms Rejection
        # ----------------------------------------------------------------------
        b2_duration = beat_durations["beat_2_jailbreak"]
        log(f"Beat 2: Injecting Jailbreak Attack & Airlock Rejection ({b2_duration:.2f}s)...")
        t0 = time.perf_counter()
        
        # Click Preset 1: "Inject Jailbreak"
        btn_jailbreak = page.locator('button[onclick*="setPreset(1)"]')
        await btn_jailbreak.click()
        await asyncio.sleep(1.2)

        # Click Execute Airlock & Route
        btn_submit = page.locator("#btn-submit")
        await btn_submit.click()
        
        # Wait for rejection verdict card
        await page.wait_for_selector("text=REJECTED (HTTP 403)", timeout=15000)
        await asyncio.sleep(1.0)
        
        # Switch to Security tab to display compile-time regex diagnostics
        tab_security = page.locator("#tab-btn-security")
        await tab_security.click()
        await asyncio.sleep(1.5)
        await page.hover("#sec-reason")

        elapsed_b2 = time.perf_counter() - t0
        if elapsed_b2 < b2_duration:
            await asyncio.sleep(b2_duration - elapsed_b2)

        # ----------------------------------------------------------------------
        # Beat 3: Valid System Query & Admitted Inference
        # ----------------------------------------------------------------------
        b3_duration = beat_durations["beat_3_valid"]
        log(f"Beat 3: Submitting Valid Query & Gateway Streaming ({b3_duration:.2f}s)...")
        t0 = time.perf_counter()

        # Switch back to completion tab
        tab_completion = page.locator("#tab-btn-completion")
        await tab_completion.click()
        await asyncio.sleep(0.5)

        # Click Preset 2: "Valid System Query"
        btn_valid = page.locator('button[onclick*="setPreset(2)"]')
        await btn_valid.click()
        await asyncio.sleep(1.2)

        # Click Execute Airlock & Route
        await btn_submit.click()

        # Wait until request completes and button re-enables
        await page.wait_for_function(
            "document.getElementById('btn-submit').disabled === false && document.getElementById('spinner').classList.contains('hidden')",
            timeout=50000,
        )
        await page.wait_for_selector("text=PASSED (HTTP 200)", timeout=10000)
        await asyncio.sleep(1.5)

        # Smooth hover over model served and completion
        await page.hover("#model-served-text")
        await asyncio.sleep(2.0)

        elapsed_b3 = time.perf_counter() - t0
        if elapsed_b3 < b3_duration:
            await asyncio.sleep(b3_duration - elapsed_b3)

        # ----------------------------------------------------------------------
        # Beat 4: Semantic Cache Replay & USD Savings
        # ----------------------------------------------------------------------
        b4_duration = beat_durations["beat_4_cache"]
        log(f"Beat 4: Sub-Millisecond Semantic Cache Replay ({b4_duration:.2f}s)...")
        t0 = time.perf_counter()

        # Click Preset 6: "Semantic Cache Replay"
        btn_cache = page.locator('button[onclick*="setPreset(6)"]')
        await btn_cache.click()
        await asyncio.sleep(1.2)

        # Click Execute Airlock & Route
        await btn_submit.click()

        # Instant wait for Cache Hit badge
        await page.wait_for_selector("#cache-badge:not(.hidden)", timeout=10000)
        await asyncio.sleep(1.5)

        # Highlight USD Saved HUD card and Cache Hit Rate card
        await page.hover("#hud-usd-saved")
        await asyncio.sleep(2.0)
        await page.hover("#hud-cache-hit-rate")
        await asyncio.sleep(1.5)

        elapsed_b4 = time.perf_counter() - t0
        if elapsed_b4 < b4_duration:
            await asyncio.sleep(b4_duration - elapsed_b4)

        # ----------------------------------------------------------------------
        # Beat 5: Outro & Telemetry HUD Summary
        # ----------------------------------------------------------------------
        b5_duration = beat_durations["beat_5_outro"]
        log(f"Beat 5: Outro & Telemetry Ledger ({b5_duration:.2f}s)...")
        t0 = time.perf_counter()
        await page.hover("#hud-tokens-conserved")
        await asyncio.sleep(2.0)
        await page.hover("#header-usd-saved")
        await asyncio.sleep(2.0)

        elapsed_b5 = time.perf_counter() - t0
        if elapsed_b5 < b5_duration:
            await asyncio.sleep(b5_duration - elapsed_b5)

        # Retrieve video file path and close context
        video_path = await page.video.path()
        await context.close()
        await browser.close()
        log(f"Raw screen recording saved: {video_path}")
        return video_path


def merge_video_audio(raw_video_path: str, audio_path: str, output_path: str):
    """
    Step C: High-Definition MP4 Export via FFmpeg (H.264/AAC, 1080p, 60fps).
    """
    log("=== STEP C: Video & Audio Synchronization and Export (FFmpeg) ===")
    ffmpeg_exe = imageio_ffmpeg.get_ffmpeg_exe()

    # Mux video and audio. Ensure video freezes on last frame if video is slightly shorter than audio,
    # and terminates exactly when audio finishes.
    cmd = [
        ffmpeg_exe,
        "-y",
        "-i", str(raw_video_path),
        "-i", str(audio_path),
        "-filter_complex", "[0:v]tpad=stop_mode=clone:stop_duration=10[v]",
        "-map", "[v]",
        "-map", "1:a",
        "-c:v", "libx264",
        "-preset", "medium",
        "-crf", "18",
        "-pix_fmt", "yuv420p",
        "-c:a", "aac",
        "-b:a", "192k",
        "-shortest",
        str(output_path),
    ]

    log(f"Executing FFmpeg high-definition encoding...")
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        log(f"FFmpeg error: {res.stderr}")
        raise RuntimeError(f"FFmpeg failed: {res.stderr}")

    file_size_mb = os.path.getsize(output_path) / (1024 * 1024)
    log(f"SUCCESS! Output MP4 exported: {output_path}")
    log(f"Final File Size: {file_size_mb:.2f} MB")
    return output_path, file_size_mb


async def main():
    t_start = time.perf_counter()
    log("Starting End-to-End Headless Demo Video Generator...")

    # Step A: Neural Audio
    beat_durations, total_audio_duration = await generate_neural_audio()

    # Step B: Headless Browser Recording
    raw_video_path = await record_browser_interaction(beat_durations)

    # Step C: Merge & Export
    final_path, file_size_mb = merge_video_audio(
        raw_video_path, str(DEMO_AUDIO_PATH), str(FINAL_VIDEO_PATH)
    )

    # Clean up temporary artifact directory
    shutil.rmtree(TEMP_DIR, ignore_errors=True)
    shutil.rmtree(RECORDING_DIR, ignore_errors=True)

    elapsed_total = time.perf_counter() - t_start
    print("\n" + "=" * 80)
    print("DEMO VIDEO GENERATION COMPLETE")
    print(f"Path: {final_path}")
    print(f"Size: {file_size_mb:.2f} MB")
    print(f"Duration: {total_audio_duration:.2f} seconds")
    print(f"Total Pipeline Runtime: {elapsed_total:.2f} seconds")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
