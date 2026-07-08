"""
Visual analysis module for Audio Stego Solver.

FIXED (v1.1):
  - _generate_ffmpeg_spectrogram no longer called twice (was in run() AND in except block)
  - Stereo/mono detection hardened: checks y.ndim before indexing y[0]/y[1]
  - Zero-length audio guard added before librosa.load
  - LSB audio forensics analysis added (Phase 7)
  - Channel difference analysis added (Phase 7)
"""

import os
from typing import Any, Dict

from .findings import Finding, Severity
from .logger import get_logger
from .utils import run_command, tool_available

logger = get_logger("audio_stego.visual")


class VisualAnalyzer:
    """Generates visual representations of audio files and performs audio forensics."""

    def __init__(self, config, output_dir: str):
        self.config = config
        self.output_dir = output_dir
        self.images_dir = os.path.join(output_dir, "images")
        os.makedirs(self.images_dir, exist_ok=True)
        self.results: Dict[str, Any] = {
            "spectrogram": None,
            "waveform": None,
            "fft": None,
            "lsb_analysis": None,
            "channel_diff": None,
            "warnings": [],
            "findings": [],
        }

    def run(self, audio_path: str) -> Dict[str, Any]:
        """Generate all visual analyses and audio forensic checks."""
        logger.info(f"Starting visual analysis: {audio_path}")

        # Check for zero-length file before attempting librosa
        if os.path.getsize(audio_path) == 0:
            self.results["warnings"].append("File is empty — skipping visual analysis")
            return self.results

        self._generate_spectrogram(audio_path)
        self._generate_waveform(audio_path)
        self._generate_fft(audio_path)
        # FIXED: ffmpeg spectrogram called only as fallback (not again after librosa)
        if not self.results["spectrogram"]:
            self._generate_ffmpeg_spectrogram(audio_path)

        # Phase 7: audio forensic analyses
        self._analyze_lsb(audio_path)
        self._analyze_channel_difference(audio_path)

        logger.info("Visual analysis complete")
        return self.results

    # ------------------------------------------------------------------
    # Spectrogram
    # ------------------------------------------------------------------

    def _generate_spectrogram(self, path: str):
        """Generate spectrogram using librosa/matplotlib."""
        spec_path = os.path.join(self.images_dir, "spectrogram.png")

        try:
            import librosa
            import librosa.display
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            import numpy as np

            fft_size  = self.config.getint("spectrogram", "fft_size", 2048)
            hop_length = self.config.getint("spectrogram", "hop_length", 512)
            cmap      = self.config.get("spectrogram", "colormap", "viridis")

            y, sr = librosa.load(path, sr=None, mono=False)

            # FIXED: robust stereo/mono detection
            if y.ndim == 2 and y.shape[0] >= 2:
                channels      = [y[0], y[1]]
                channel_names = ["Left", "Right"]
                fig, axes = plt.subplots(2, 2, figsize=(20, 12))
            else:
                # mono — y may be shape (n,) or (1, n)
                mono = y[0] if y.ndim == 2 else y
                channels      = [mono]
                channel_names = ["Mono"]
                fig, axes_row = plt.subplots(1, 2, figsize=(20, 6))
                axes = [axes_row]

            for idx, (channel, ch_name) in enumerate(zip(channels, channel_names)):
                D    = librosa.stft(channel, n_fft=fft_size, hop_length=hop_length)
                S_db = librosa.amplitude_to_db(np.abs(D), ref=np.max)

                ax_spec = axes[idx][0]
                img = librosa.display.specshow(
                    S_db, sr=sr, hop_length=hop_length,
                    x_axis="time", y_axis="hz",
                    cmap=cmap, ax=ax_spec,
                )
                ax_spec.set_title(f"Spectrogram ({ch_name})")
                plt.colorbar(img, ax=ax_spec, format="%+2.0f dB")

                mel    = librosa.feature.melspectrogram(
                    y=channel, sr=sr, n_fft=fft_size, hop_length=hop_length
                )
                mel_db = librosa.power_to_db(mel, ref=np.max)
                ax_mel = axes[idx][1]
                img2 = librosa.display.specshow(
                    mel_db, sr=sr, hop_length=hop_length,
                    x_axis="time", y_axis="mel",
                    cmap=cmap, ax=ax_mel,
                )
                ax_mel.set_title(f"Mel Spectrogram ({ch_name})")
                plt.colorbar(img2, ax=ax_mel, format="%+2.0f dB")

            plt.suptitle(f"Spectrogram: {os.path.basename(path)}", fontsize=14)
            plt.tight_layout()
            plt.savefig(spec_path, dpi=150, bbox_inches="tight")
            plt.close()

            self.results["spectrogram"] = spec_path
            logger.info(f"Spectrogram → {spec_path}")

        except ImportError as e:
            self.results["warnings"].append(f"librosa/matplotlib not available: {e}")
            # Fallback handled by caller (run()) — not here
        except Exception as e:
            logger.error(f"Spectrogram failed: {e}")
            self.results["warnings"].append(f"Spectrogram failed: {e}")

    # ------------------------------------------------------------------
    # Waveform
    # ------------------------------------------------------------------

    def _generate_waveform(self, path: str):
        wave_path = os.path.join(self.images_dir, "waveform.png")
        try:
            import librosa
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            import numpy as np

            y, sr = librosa.load(path, sr=None, mono=False)

            if y.ndim == 2 and y.shape[0] >= 2:
                duration = y.shape[1] / sr
                time_ax  = np.linspace(0, duration, y.shape[1])
                fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(20, 8), sharex=True)
                ax1.plot(time_ax, y[0], color="steelblue", linewidth=0.3, alpha=0.8)
                ax1.set_title("Waveform — Left Channel")
                ax1.set_ylabel("Amplitude")
                ax1.grid(True, alpha=0.3)
                ax2.plot(time_ax, y[1], color="coral", linewidth=0.3, alpha=0.8)
                ax2.set_title("Waveform — Right Channel")
                ax2.set_ylabel("Amplitude")
                ax2.set_xlabel("Time (s)")
                ax2.grid(True, alpha=0.3)
            else:
                mono     = y[0] if y.ndim == 2 else y
                duration = len(mono) / sr
                time_ax  = np.linspace(0, duration, len(mono))
                fig, ax1 = plt.subplots(figsize=(20, 4))
                ax1.plot(time_ax, mono, color="steelblue", linewidth=0.3, alpha=0.8)
                ax1.set_title("Waveform")
                ax1.set_ylabel("Amplitude")
                ax1.set_xlabel("Time (s)")
                ax1.grid(True, alpha=0.3)

            plt.suptitle(f"Waveform: {os.path.basename(path)}", fontsize=14)
            plt.tight_layout()
            plt.savefig(wave_path, dpi=150, bbox_inches="tight")
            plt.close()
            self.results["waveform"] = wave_path
            logger.info(f"Waveform → {wave_path}")

        except ImportError as e:
            self.results["warnings"].append(f"librosa not available for waveform: {e}")
        except Exception as e:
            logger.error(f"Waveform failed: {e}")
            self.results["warnings"].append(f"Waveform failed: {e}")

    # ------------------------------------------------------------------
    # FFT
    # ------------------------------------------------------------------

    def _generate_fft(self, path: str):
        fft_path = os.path.join(self.images_dir, "fft.png")
        try:
            import librosa
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            import numpy as np

            y, sr = librosa.load(path, sr=None, mono=True)
            N         = len(y)
            fft_vals  = np.fft.rfft(y)
            fft_mag   = np.abs(fft_vals)
            fft_mag_db = 20 * np.log10(fft_mag + 1e-10)
            freqs     = np.fft.rfftfreq(N, d=1.0 / sr)

            fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(20, 10))
            ax1.plot(freqs, fft_mag, color="royalblue", linewidth=0.5)
            ax1.set_xlabel("Frequency (Hz)")
            ax1.set_ylabel("Magnitude")
            ax1.set_title("FFT Frequency Spectrum (Linear)")
            ax1.grid(True, alpha=0.3)
            ax1.set_xlim(0, sr // 2)

            ax2.plot(freqs, fft_mag_db, color="firebrick", linewidth=0.5)
            ax2.set_xlabel("Frequency (Hz)")
            ax2.set_ylabel("Magnitude (dB)")
            ax2.set_title("FFT Frequency Spectrum (dB Scale)")
            ax2.grid(True, alpha=0.3)
            ax2.set_xlim(0, sr // 2)

            top_indices = np.argsort(fft_mag)[-10:]
            for idx in top_indices:
                if freqs[idx] > 20:
                    ax1.axvline(freqs[idx], color="red", alpha=0.3, linewidth=0.5)

            plt.suptitle(f"FFT: {os.path.basename(path)}", fontsize=14)
            plt.tight_layout()
            plt.savefig(fft_path, dpi=150, bbox_inches="tight")
            plt.close()
            self.results["fft"] = fft_path
            logger.info(f"FFT → {fft_path}")

        except ImportError as e:
            self.results["warnings"].append(f"librosa not available for FFT: {e}")
        except Exception as e:
            logger.error(f"FFT failed: {e}")
            self.results["warnings"].append(f"FFT failed: {e}")

    # ------------------------------------------------------------------
    # ffmpeg spectrogram fallback
    # ------------------------------------------------------------------

    def _generate_ffmpeg_spectrogram(self, path: str):
        """Generate spectrogram using ffmpeg (fallback when librosa unavailable)."""
        if not tool_available("ffmpeg"):
            return

        spec_path = os.path.join(self.images_dir, "spectrogram_ffmpeg.png")
        cmd = [
            "ffmpeg", "-i", path,
            "-lavfi", "showspectrumpic=s=1920x1080:mode=combined:color=intensity:gain=5",
            "-frames:v", "1", spec_path, "-y",
        ]
        rc, _, err = run_command(cmd, timeout=60)
        if rc == 0 and os.path.exists(spec_path):
            self.results["spectrogram_ffmpeg"] = spec_path
            logger.info(f"ffmpeg spectrogram → {spec_path}")

        wave_path = os.path.join(self.images_dir, "waveform_ffmpeg.png")
        cmd2 = [
            "ffmpeg", "-i", path,
            "-lavfi", "showwavespic=s=1920x400:colors=steelblue",
            "-frames:v", "1", wave_path, "-y",
        ]
        rc2, _, _ = run_command(cmd2, timeout=60)
        if rc2 == 0 and os.path.exists(wave_path):
            self.results["waveform_ffmpeg"] = wave_path

    # ------------------------------------------------------------------
    # Phase 7: LSB analysis
    # ------------------------------------------------------------------

    def _analyze_lsb(self, path: str):
        """
        Extract the least-significant bit of each audio sample.
        Checks if LSB stream contains significant non-random content
        (would indicate LSB steganography).
        """
        try:
            import numpy as np
            try:
                import librosa
                y, sr = librosa.load(path, sr=None, mono=True)
                samples = (y * 32768).astype(np.int16)
            except ImportError:
                import wave
                if not path.lower().endswith(".wav"):
                    return
                with wave.open(path, "rb") as wf:
                    raw = wf.readframes(wf.getnframes())
                    samples = np.frombuffer(raw, dtype=np.int16)

            lsb_bits = (samples & 1).astype(np.uint8)

            # Convert bits to bytes
            n_bytes = len(lsb_bits) // 8
            if n_bytes < 4:
                return

            lsb_bytes = np.packbits(lsb_bits[:n_bytes * 8])

            # Entropy of LSB stream
            from collections import Counter
            import math
            counts = Counter(lsb_bytes.tobytes())
            total  = len(lsb_bytes)
            entropy = -sum(
                (c / total) * math.log2(c / total)
                for c in counts.values() if c
            )

            # Decode LSB as ASCII
            lsb_text = "".join(
                chr(b) for b in lsb_bytes[:2000] if 0x20 <= b < 0x7F
            )
            printable_ratio = len(lsb_text) / max(n_bytes, 1)

            result = {
                "entropy": round(entropy, 4),
                "n_samples": len(samples),
                "n_lsb_bytes": n_bytes,
                "printable_ratio": round(printable_ratio, 4),
                "lsb_text_preview": lsb_text[:200],
            }
            self.results["lsb_analysis"] = result

            # High printable ratio → likely LSB-encoded text
            if printable_ratio >= 0.70:
                f = Finding(
                    module="visual",
                    title="LSB Steganography — High Printable Ratio",
                    severity=Severity.HIGH,
                    confidence=min(0.95, 0.50 + printable_ratio * 0.45),
                    value=lsb_text[:300],
                    evidence=f"LSB stream: {printable_ratio:.0%} printable chars, entropy={entropy:.2f}",
                    reason="High printable ratio in LSB stream is a strong indicator of hidden text",
                    false_positive_risk="Low if printable ratio > 80%; medium 70–80%",
                )
                self.results["findings"].append(f.to_dict())
                logger.info(
                    f"LSB analysis: printable={printable_ratio:.0%} "
                    f"entropy={entropy:.4f} — likely LSB steg"
                )
            else:
                logger.info(
                    f"LSB analysis: printable={printable_ratio:.0%} "
                    f"entropy={entropy:.4f} — no significant pattern"
                )

        except Exception as e:
            logger.debug(f"LSB analysis failed: {e}")
            self.results["warnings"].append(f"LSB analysis failed: {e}")

    # ------------------------------------------------------------------
    # Phase 7: Stereo channel difference
    # ------------------------------------------------------------------

    def _analyze_channel_difference(self, path: str):
        """
        Compute left−right channel difference.
        If the difference channel contains data while the individual channels
        appear normal, this may indicate dual-channel hidden content.
        """
        try:
            import numpy as np
            import librosa

            y, sr = librosa.load(path, sr=None, mono=False)
            if y.ndim < 2 or y.shape[0] < 2:
                return   # Mono file

            left  = y[0].astype(np.float64)
            right = y[1].astype(np.float64)
            diff  = left - right

            rms_left  = float(np.sqrt(np.mean(left  ** 2)))
            rms_right = float(np.sqrt(np.mean(right ** 2)))
            rms_diff  = float(np.sqrt(np.mean(diff  ** 2)))

            # Ratio: how much energy is in the difference channel vs the sum
            rms_sum = (rms_left + rms_right) / 2
            diff_ratio = rms_diff / max(rms_sum, 1e-10)

            result = {
                "rms_left":   round(rms_left, 6),
                "rms_right":  round(rms_right, 6),
                "rms_diff":   round(rms_diff, 6),
                "diff_ratio": round(diff_ratio, 6),
            }
            self.results["channel_diff"] = result

            if diff_ratio > 0.30:
                f = Finding(
                    module="visual",
                    title="Large Stereo Channel Difference",
                    severity=Severity.MEDIUM,
                    confidence=min(0.80, 0.40 + diff_ratio * 0.5),
                    value=f"Diff ratio: {diff_ratio:.4f}",
                    evidence=(
                        f"L RMS={rms_left:.4f}, R RMS={rms_right:.4f}, "
                        f"diff RMS={rms_diff:.4f}"
                    ),
                    reason="Unusually large L−R difference may indicate dual-channel hidden content",
                    false_positive_risk="Medium — stereo music naturally has channel differences",
                )
                self.results["findings"].append(f.to_dict())
                logger.info(f"Channel diff ratio: {diff_ratio:.4f} — notable difference")

        except ImportError:
            pass  # librosa not available
        except Exception as e:
            logger.debug(f"Channel difference analysis failed: {e}")
