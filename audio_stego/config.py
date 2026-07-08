"""
Configuration management for Audio Stego Solver.
Loads and provides access to configuration settings.
"""

import configparser
from pathlib import Path
from typing import Any, Dict, Optional

# Default configuration
DEFAULT_CONFIG: Dict[str, Dict[str, Any]] = {
    "general": {
        "output_dir": "results",
        "log_dir": "logs",
        "log_file": "run.log",
        "max_workers": "8",
        "timeout": "60",
        "verbose": "false",
    },
    "analysis": {
        "run_binwalk": "true",
        "run_foremost": "true",
        "run_scalpel": "true",
        "run_steghide": "true",
        "run_stegseek": "true",
        "run_strings": "true",
        "run_hexdump": "true",
        "run_entropy": "true",
        "run_spectrogram": "true",
        "run_waveform": "true",
        "run_fft": "true",
        "run_ocr": "true",
        "run_qr": "true",
        "run_morse": "true",
        "run_dtmf": "true",
        "run_sstv": "true",
        "run_multimon": "true",
        "run_minimodem": "true",
        "run_metadata": "true",
        "run_plugins": "true",
    },
    "steghide": {
        "wordlist": "/usr/share/wordlists/rockyou.txt",
        "passphrase": "",
        "try_empty_passphrase": "true",
    },
    "stegseek": {
        "wordlist": "/usr/share/wordlists/rockyou.txt",
    },
    "strings": {
        "min_length": "4",
    },
    "entropy": {
        "block_size": "256",
    },
    "spectrogram": {
        "fft_size": "2048",
        "hop_length": "512",
        "colormap": "viridis",
    },
    "flags": {
        "patterns": "flag{,FLAG{,HTB{,THM{,picoCTF{,CTF{,Hero{,Hack{,iris{,uiuctf{,corCTF{,NACTF{",
    },
    "tools": {
        "ffmpeg": "ffmpeg",
        "ffprobe": "ffprobe",
        "exiftool": "exiftool",
        "mediainfo": "mediainfo",
        "binwalk": "binwalk",
        "foremost": "foremost",
        "scalpel": "scalpel",
        "steghide": "steghide",
        "stegseek": "stegseek",
        "multimon_ng": "multimon-ng",
        "minimodem": "minimodem",
        "tesseract": "tesseract",
        "zbarimg": "zbarimg",
        "file": "file",
        "xxd": "xxd",
        "hexdump": "hexdump",
        "strings": "strings",
    },
}

CONFIG_FILE_LOCATIONS = [
    Path.home() / ".config" / "audio-stego" / "config.ini",
    Path("/etc/audio-stego/config.ini"),
    Path("audio_stego.ini"),
    Path("config.ini"),
]


class Config:
    """Configuration manager for Audio Stego Solver."""

    def __init__(self, config_file: Optional[str] = None):
        self._config = configparser.ConfigParser()
        self._load_defaults()

        # Search for config file
        config_paths = []
        if config_file:
            config_paths.append(Path(config_file))
        config_paths.extend(CONFIG_FILE_LOCATIONS)

        for path in config_paths:
            if path.exists():
                self._config.read(str(path))
                break

    def _load_defaults(self):
        """Load default configuration values."""
        for section, values in DEFAULT_CONFIG.items():
            if not self._config.has_section(section):
                self._config.add_section(section)
            for key, value in values.items():
                self._config.set(section, key, str(value))

    def get(self, section: str, key: str, fallback: Any = None) -> str:
        """Get a configuration value as string."""
        return self._config.get(section, key, fallback=str(fallback) if fallback is not None else None)

    def getbool(self, section: str, key: str, fallback: bool = False) -> bool:
        """Get a configuration value as boolean."""
        return self._config.getboolean(section, key, fallback=fallback)

    def getint(self, section: str, key: str, fallback: int = 0) -> int:
        """Get a configuration value as integer."""
        return self._config.getint(section, key, fallback=fallback)

    def getfloat(self, section: str, key: str, fallback: float = 0.0) -> float:
        """Get a configuration value as float."""
        return self._config.getfloat(section, key, fallback=fallback)

    @property
    def output_dir(self) -> str:
        return self.get("general", "output_dir", "results")

    @property
    def log_dir(self) -> str:
        return self.get("general", "log_dir", "logs")

    @property
    def log_file(self) -> str:
        return self.get("general", "log_file", "run.log")

    @property
    def max_workers(self) -> int:
        return self.getint("general", "max_workers", 8)

    @property
    def timeout(self) -> int:
        return self.getint("general", "timeout", 60)

    @property
    def verbose(self) -> bool:
        return self.getbool("general", "verbose", False)

    @property
    def flag_patterns(self) -> list:
        raw = self.get("flags", "patterns", "flag{,FLAG{")
        return [p.strip() for p in raw.split(",") if p.strip()]

    @property
    def tool_path(self) -> Dict[str, str]:
        """Get tool paths dictionary."""
        tools = {}
        if self._config.has_section("tools"):
            for key, value in self._config.items("tools"):
                tools[key] = value
        return tools

    def save_default(self, path: str):
        """Save default config to a file."""
        with open(path, "w") as f:
            self._config.write(f)


def generate_default_config(output_path: str = "audio_stego.ini"):
    """Generate a default configuration file."""
    cfg = Config()
    cfg.save_default(output_path)
    return output_path
