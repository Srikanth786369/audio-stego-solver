"""
Plugin manager for Audio Stego Solver.
Automatically discovers and executes all plugins.
"""

import importlib
import importlib.util
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

from ..logger import get_logger
from .base_plugin import BasePlugin

logger = get_logger("audio_stego.plugins")


class PluginManager:
    """Discovers, loads, and executes Audio Stego Solver plugins."""

    PLUGIN_DIRS: List[Path] = [
        Path(__file__).parent,  # Built-in plugins
        Path.home() / ".config" / "audio-stego" / "plugins",  # User plugins
        Path("/etc/audio-stego/plugins"),  # System plugins
    ]

    def __init__(self, config):
        self.config = config
        self._plugins: Optional[List[BasePlugin]] = None

    def discover(self) -> List[BasePlugin]:
        """
        Discover and instantiate all available plugins.

        Returns:
            List of instantiated plugin objects
        """
        if self._plugins is not None:
            return self._plugins

        plugins: List[BasePlugin] = []
        seen_names: set = set()

        for plugin_dir in self.PLUGIN_DIRS:
            if not plugin_dir.exists():
                continue

            for fpath in sorted(plugin_dir.glob("*_plugin.py")):
                module_name = fpath.stem
                try:
                    plugin_cls = self._load_plugin_module(fpath, module_name)
                    if plugin_cls is None:
                        continue

                    instance = plugin_cls(self.config)
                    if instance.name in seen_names:
                        logger.debug(f"Skipping duplicate plugin: {instance.name}")
                        continue

                    seen_names.add(instance.name)
                    plugins.append(instance)
                    logger.info(f"Loaded plugin: {instance.name} v{instance.version}")

                except Exception as e:
                    logger.error(f"Failed to load plugin {fpath}: {e}")

        self._plugins = plugins
        logger.info(f"Discovered {len(plugins)} plugin(s)")
        return plugins

    def _load_plugin_module(self, fpath: Path, module_name: str) -> Optional[Type[BasePlugin]]:
        """Load a plugin module and return its plugin class."""
        try:
            # Ensure the parent package is importable
            try:
                import audio_stego.plugins as _pkg  # noqa: F401
            except ImportError:
                pass

            spec = importlib.util.spec_from_file_location(
                f"audio_stego.plugins.{module_name}", fpath,
            )
            if spec is None or spec.loader is None:
                return None

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)  # type: ignore

            # Find the plugin class
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                try:
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, BasePlugin)
                        and attr is not BasePlugin
                        and attr.name != "base"
                    ):
                        return attr
                except TypeError:
                    pass

            logger.debug(f"No valid BasePlugin subclass found in {fpath}")
            return None

        except Exception as e:
            logger.error(f"Error loading plugin module {fpath}: {e}")
            return None

    def run_all(
        self,
        audio_path: str,
        output_dir: str,
        results: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Run all discovered plugins against the audio file.

        Args:
            audio_path: Path to audio file
            output_dir: Output directory
            results: Existing analysis results

        Returns:
            Dict mapping plugin names to their results
        """
        plugins = self.discover()
        if not plugins:
            logger.info("No plugins to execute")
            return {}

        plugin_results: Dict[str, Any] = {}
        plugins_output_dir = os.path.join(output_dir, "plugins")
        os.makedirs(plugins_output_dir, exist_ok=True)

        logger.info(f"Running {len(plugins)} plugin(s)")

        for plugin in plugins:
            logger.info(f"Running plugin: {plugin.name}")
            start = time.time()
            try:
                plugin_out_dir = os.path.join(plugins_output_dir, plugin.name)
                os.makedirs(plugin_out_dir, exist_ok=True)

                findings = plugin.run(audio_path, plugin_out_dir, results)
                plugin_results[plugin.name] = findings or {}
                logger.info(f"Plugin {plugin.name} completed")

            except Exception as e:
                # A plugin failure must never abort the scan — logged and
                # recorded per-plugin, execution continues with the next one.
                logger.error(f"Plugin {plugin.name} failed: {e}")
                plugin_results[plugin.name] = {"error": str(e)}

            plugin_results[plugin.name]["execution_time"] = round(time.time() - start, 4)
            plugin_results[plugin.name]["metadata"] = plugin.metadata()

        # Write plugin summary
        self._write_plugin_summary(plugins_output_dir, plugin_results)

        # Merge plugin flag findings into main results
        self._merge_flags(results, plugin_results)

        return plugin_results

    def _write_plugin_summary(self, output_dir: str, plugin_results: Dict[str, Any]):
        """Write a summary of all plugin results."""
        lines = ["=" * 60, "PLUGIN EXECUTION SUMMARY", "=" * 60]
        for plugin_name, result in plugin_results.items():
            lines.append(f"\n[{plugin_name}]")
            if isinstance(result, dict):
                meta = result.get("metadata") or {}
                if meta:
                    lines.append(f"  v{meta.get('version','?')} by {meta.get('author','?')}"
                                 f" — {meta.get('description','')}")
                    if meta.get("dependencies"):
                        lines.append(f"  Dependencies: {', '.join(meta['dependencies'])}")
                if "execution_time" in result:
                    lines.append(f"  Execution time: {result['execution_time']:.3f}s")
                if result.get("error"):
                    lines.append(f"  ERROR: {result['error']}")
                elif result.get("flags_found"):
                    lines.append(f"  FLAGS: {result['flags_found']}")
                elif result.get("findings"):
                    lines.append(f"  Findings: {len(result['findings'])}")
                else:
                    lines.append("  No significant findings")
            else:
                lines.append(f"  Result: {str(result)[:200]}")

        summary_path = os.path.join(output_dir, "plugin_summary.txt")
        with open(summary_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def _merge_flags(self, results: Dict[str, Any], plugin_results: Dict[str, Any]):
        """Merge plugin-found flags into the main results dict."""
        main_flags = results.setdefault("flags", {}).setdefault("flags_found", [])
        for plugin_name, result in plugin_results.items():
            if isinstance(result, dict):
                for flag in result.get("flags_found", []):
                    flag["source"] = f"plugin:{plugin_name}"
                    main_flags.append(flag)
