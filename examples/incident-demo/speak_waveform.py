"""
Speak with Waveform Visualization

A custom speak tool that uses Amazon Polly for TTS and displays
an animated waveform while the audio plays.

Uses subprocess to handle macOS main-thread requirements for pygame/SDL.

Usage:
    from speak_waveform import speak_with_waveform

    agent = Agent(
        model=model,
        tools=[speak_with_waveform, ...],
    )

Requirements:
    pip install boto3 pygame numpy
"""

import os
import subprocess
import sys
import tempfile
from typing import Optional

import boto3


def synthesize_speech(
    text: str,
    voice_id: str = "Matthew",
    region: Optional[str] = None,
    output_format: str = "mp3",
) -> bytes:
    """Call Amazon Polly to synthesize speech."""
    kwargs = {}
    if region:
        kwargs["region_name"] = region

    polly = boto3.client("polly", **kwargs)

    response = polly.synthesize_speech(
        Text=text,
        OutputFormat=output_format,
        VoiceId=voice_id,
        Engine="neural",  # Better quality
    )

    return response["AudioStream"].read()


def speak_with_waveform(
    text: str,
    voice_id: str = "Matthew",
    region: Optional[str] = None,
) -> dict:
    """
    Speak text using Amazon Polly with a waveform visualization.

    Args:
        text: The text to speak
        voice_id: Polly voice ID (default: Matthew)
        region: AWS region (optional, uses default if not specified)

    Returns:
        Dictionary with success status and details
    """
    try:
        # Synthesize speech
        audio_data = synthesize_speech(text, voice_id, region)

        # Write MP3 data to temp file
        with tempfile.NamedTemporaryFile(suffix=".mp3", delete=False) as f:
            f.write(audio_data)
            audio_path = f.name

        try:
            # Run visualizer in subprocess (handles main-thread requirement)
            result = subprocess.run(
                [sys.executable, __file__, "--play", audio_path],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode != 0:
                return {
                    "success": False,
                    "error": result.stderr,
                    "summary": f"Visualizer failed: {result.stderr[:100]}",
                }
        finally:
            # Clean up temp file
            os.unlink(audio_path)

        return {
            "success": True,
            "text": text,
            "voice_id": voice_id,
            "characters": len(text),
            "summary": f"Spoke {len(text)} characters with waveform visualization",
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "summary": f"Failed to speak: {e}",
        }


def create_speak_tool():
    """Create the speak tool for use with strands agents."""
    from strands import tool

    @tool
    def speak(text: str, voice_id: str = "Matthew") -> dict:
        """
        Speak text aloud using Amazon Polly with a waveform visualization.

        Use this to announce alerts or important information audibly.
        A visual waveform will appear while speaking.

        Args:
            text: The text to speak aloud. Keep it brief and clear.
            voice_id: The Polly voice to use. Default is Matthew (clear male voice).
                     Other options: Joanna, Amy, Brian, Ivy, Kendra, etc.
        """
        return speak_with_waveform(text, voice_id)

    return speak


# =============================================================================
# SUBPROCESS VISUALIZER (runs on main thread)
# =============================================================================


def _run_visualizer(audio_path: str):
    """Run the pygame visualizer. Called as subprocess to ensure main thread."""
    import math
    import random

    import pygame

    # Initialize pygame (now on main thread)
    pygame.init()
    pygame.mixer.init()

    # Create window
    width, height = 400, 150
    screen = pygame.display.set_mode((width, height), pygame.NOFRAME)
    pygame.display.set_caption("Alert")

    # Colors
    bg_color = (20, 20, 30)
    bar_color = (0, 200, 255)

    # Load and play audio
    pygame.mixer.music.load(audio_path)
    pygame.mixer.music.play()

    # Animate waveform
    clock = pygame.time.Clock()
    font = pygame.font.Font(None, 28)

    # Number of bars
    num_bars = 40
    bar_width = (width - 40) // num_bars
    bar_gap = 2

    # Smooth amplitude values for each bar
    bar_amplitudes = [0.1] * num_bars
    target_amplitudes = [0.1] * num_bars

    frame = 0
    running = True

    while running:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                running = False
            elif event.type == pygame.KEYDOWN and event.key == pygame.K_ESCAPE:
                running = False

        # Check if music is still playing
        if not pygame.mixer.music.get_busy():
            running = False
            continue

        frame += 1

        # Update target amplitudes periodically (simulated based on "speech")
        if frame % 3 == 0:
            for i in range(num_bars):
                # Create wave-like pattern with randomness
                wave = math.sin(frame * 0.1 + i * 0.3) * 0.3 + 0.5
                noise = random.uniform(0.7, 1.3)
                target_amplitudes[i] = min(wave * noise, 1.0)

        # Smooth transition to targets
        for i in range(num_bars):
            bar_amplitudes[i] += (target_amplitudes[i] - bar_amplitudes[i]) * 0.3

        # Draw background
        screen.fill(bg_color)

        # Draw title
        title_surface = font.render("🔊 Speaking...", True, (200, 200, 200))
        title_rect = title_surface.get_rect(center=(width // 2, 25))
        screen.blit(title_surface, title_rect)

        # Waveform area
        wave_top = 50
        wave_height = height - 70
        wave_center = wave_top + wave_height // 2

        for i in range(num_bars):
            amp = bar_amplitudes[i]
            bar_height = max(4, int(amp * wave_height * 0.8))
            x = 20 + i * bar_width
            y = wave_center - bar_height // 2

            # Color gradient from center
            center_dist = abs(i - num_bars // 2) / (num_bars // 2)
            intensity = 1.0 - center_dist * 0.4
            color = (
                int(bar_color[0] * intensity),
                int(bar_color[1] * intensity),
                int(bar_color[2] * intensity),
            )

            pygame.draw.rect(
                screen,
                color,
                (x, y, bar_width - bar_gap, bar_height),
                border_radius=2,
            )

        pygame.display.flip()
        clock.tick(30)

    pygame.mixer.music.stop()
    pygame.quit()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--play", help="Play PCM file with visualizer")
    parser.add_argument("text", nargs="*", help="Text to speak")
    args = parser.parse_args()

    if args.play:
        # Subprocess mode: play audio with visualizer
        _run_visualizer(args.play)
    elif args.text:
        # Direct mode: synthesize and play
        text = " ".join(args.text)
        print(f"Speaking: {text}")
        result = speak_with_waveform(text)
        print(f"Result: {result}")
    else:
        # Demo
        text = "Alert: Network is down. Traceroute fails at hop 3, the ISP gateway."
        print(f"Speaking: {text}")
        result = speak_with_waveform(text)
        print(f"Result: {result}")
