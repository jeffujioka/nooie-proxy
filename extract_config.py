#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""recover Nooie's shared client configuration from an owned app copy."""

import argparse
import os
import plistlib
import re
import shlex
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path


BUNDLE_ID = "com.nooie.home"
DEFAULT_APP = Path("/Applications/Nooie.app")


def app_executable(bundle: Path) -> Path:
    if bundle.is_file():
        return bundle
    for info_path in bundle.rglob("Info.plist"):
        try:
            info = plistlib.loads(info_path.read_bytes())
        except (OSError, plistlib.InvalidFileException):
            continue
        if info.get("CFBundleIdentifier") != BUNDLE_ID:
            continue
        executable = info.get("CFBundleExecutable")
        if executable:
            candidate = info_path.parent / str(executable)
            if candidate.is_file():
                return candidate
    raise RuntimeError(f"cannot find the Nooie executable below {bundle}")


def ipa_executable(ipa: Path, destination: Path) -> Path:
    with zipfile.ZipFile(ipa) as archive:
        for name in archive.namelist():
            if not name.startswith("Payload/") or not name.endswith(
                ".app/Info.plist"
            ):
                continue
            info = plistlib.loads(archive.read(name))
            if info.get("CFBundleIdentifier") != BUNDLE_ID:
                continue
            executable = info.get("CFBundleExecutable")
            if not executable:
                continue
            member = str(Path(name).parent / str(executable))
            archive.extract(member, destination)
            return destination / member
    raise RuntimeError(f"{ipa} does not contain the Nooie iOS app")


def extract_credentials(executable: Path) -> tuple[str, str]:
    process = subprocess.Popen(
        ["xcrun", "dyld_info", "-disassemble", str(executable)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    values: dict[str, str] = {}
    target: str | None = None
    literal = re.compile(r'; @"([^"]+)"')
    assert process.stdout is not None
    for line in process.stdout:
        if line.startswith("-[YRNooieConfiguration appId]:"):
            target = "app_id"
            continue
        if line.startswith("-[YRNooieConfiguration appSecret]:"):
            target = "app_secret"
            continue
        if target is not None:
            match = literal.search(line)
            if match:
                values[target] = match.group(1)
                target = None
                if len(values) == 2:
                    process.terminate()
                    break
    _, error = process.communicate()
    if len(values) != 2:
        detail = error.strip().splitlines()[-1] if error.strip() else ""
        suffix = f": {detail}" if detail else ""
        raise RuntimeError(
            "cannot recover client configuration from this binary"
            f"{suffix}; App Store IPA files may still be FairPlay-encrypted"
        )
    return values["app_id"], values["app_secret"]


def update_dotenv(path: Path, app_id: str, app_secret: str) -> None:
    replacements = {
        "NOOIE_APP_ID": app_id,
        "NOOIE_APP_SECRET": app_secret,
    }
    lines = path.read_text().splitlines() if path.exists() else []
    output = []
    found = set()
    for line in lines:
        match = re.match(
            r"^(\s*)(NOOIE_APP_ID|NOOIE_APP_SECRET)\s*=", line
        )
        if not match:
            output.append(line)
            continue
        key = match.group(2)
        output.append(f"{key}={shlex.quote(replacements[key])}")
        found.add(key)
    if found != set(replacements):
        if output and output[-1]:
            output.append("")
        output.append("# shared Nooie app-client configuration")
        for key, value in replacements.items():
            if key not in found:
                output.append(f"{key}={shlex.quote(value)}")

    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent, text=True
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(handle, "w") as stream:
            stream.write("\n".join(output) + "\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def download_ipa(output: Path, purchase: bool) -> Path:
    if shutil.which("ipatool") is None:
        raise RuntimeError(
            "ipatool is required for --download; install it with "
            "`brew install ipatool`, then run `ipatool auth login`"
        )
    command = [
        "ipatool",
        "download",
        "--bundle-identifier",
        BUNDLE_ID,
        "--output",
        str(output),
    ]
    if purchase:
        command.append("--purchase")
    subprocess.run(command, check=True)
    return output


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="extract Nooie's shared app-client values into a dotenv file"
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--source",
        type=Path,
        help="Nooie .app bundle, executable, or IPA owned by the user",
    )
    source.add_argument(
        "--download",
        action="store_true",
        help="download the owned Nooie IPA with ipatool",
    )
    parser.add_argument(
        "--purchase",
        action="store_true",
        help="ask ipatool to obtain the free App Store license if needed",
    )
    parser.add_argument(
        "--ipa-output",
        type=Path,
        default=Path("Nooie.ipa"),
        help="destination used with --download",
    )
    parser.add_argument(
        "--write",
        type=Path,
        default=Path(".env"),
        help="dotenv file to update",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.purchase and not args.download:
        raise SystemExit("--purchase requires --download")
    source = args.source
    if args.download:
        source = download_ipa(args.ipa_output, args.purchase)
    elif source is None:
        source = DEFAULT_APP
    if not source.exists():
        raise SystemExit(
            f"{source} does not exist; pass --source or use --download"
        )

    try:
        with tempfile.TemporaryDirectory(prefix="nooie-config-") as directory:
            executable = (
                ipa_executable(source, Path(directory))
                if zipfile.is_zipfile(source)
                else app_executable(source)
            )
            app_id, app_secret = extract_credentials(executable)
        update_dotenv(args.write, app_id, app_secret)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from error
    print(f"updated {args.write} with Nooie's shared client configuration")


if __name__ == "__main__":
    main()
