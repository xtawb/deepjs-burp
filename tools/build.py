#!/usr/bin/env python3
"""
Build and test the extension with nothing but a JDK — no Gradle, no network
once the Burp API jar is there.

    python tools/build.py                       # → build-local/deepjs-burp.jar
    python tools/build.py --test                # …and run the harness
    python tools/build.py --test --engine ../deepjs    # …and the parity check against the Python engine
    python tools/build.py --api burpsuite.jar   # compile against a local Burp / montoya-api jar

`./gradlew jar harness` does the same and is what CI and the BApp Store use;
this script is for machines where Gradle cannot download itself.
"""

from __future__ import annotations

import argparse
import glob
import os
import shutil
import subprocess
import sys
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
API_VERSION = "2023.12.1"       # the same artifact build.gradle names
API_URL = (f"https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/"
           f"{API_VERSION}/montoya-api-{API_VERSION}.jar")


def tool(name: str) -> str:
    home = os.environ.get("JAVA_HOME")
    if home:
        candidate = os.path.join(home, "bin", name + (".exe" if os.name == "nt" else ""))
        if os.path.isfile(candidate):
            return candidate
    found = shutil.which(name)
    if not found:
        sys.exit(f"build: `{name}` not found — install a JDK 17+ and put it on PATH or set JAVA_HOME")
    return found


def run(cmd, **kw) -> None:
    print("  $", " ".join(f'"{c}"' if " " in c else c for c in cmd))
    result = subprocess.run(cmd, **kw)
    if result.returncode != 0:
        sys.exit(result.returncode)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--api", metavar="JAR", help="montoya-api jar or burpsuite.jar to compile against")
    ap.add_argument("--out", metavar="DIR", default=os.path.join(ROOT, "build-local"), help="output directory")
    ap.add_argument("--test", action="store_true", help="run the harness (src/test)")
    ap.add_argument("--engine", metavar="PATH", help="with --test: a checkout of github.com/xtawb/deepjs to run tools/parity.py against")
    args = ap.parse_args()

    out = os.path.abspath(args.out)
    classes, test_classes = os.path.join(out, "classes"), os.path.join(out, "test-classes")
    for d in (classes, test_classes):
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d, exist_ok=True)

    api = args.api
    if not api:
        api = os.path.join(out, f"montoya-api-{API_VERSION}.jar")
        if not os.path.isfile(api):
            print(f"  downloading the Burp Montoya API {API_VERSION} from Maven Central")
            urllib.request.urlretrieve(API_URL, api)
    api = os.path.abspath(api)

    sources = sorted(glob.glob(os.path.join(ROOT, "src", "main", "java", "deepjs", "*", "*.java")))
    # -implicit:none: burpsuite.jar ships the API as *source*; without this javac would
    # compile those sources into our output directory.
    run([tool("javac"), "--release", "17", "-encoding", "UTF-8", "-implicit:none", "-cp", api, "-d", classes, *sources])

    jar = os.path.join(out, "deepjs-burp.jar")
    if os.path.exists(jar):
        os.remove(jar)
    # Only our own classes: a copy of the Burp API inside the jar would be loaded by the
    # extension's class loader and no longer match Burp's own types.
    run([tool("jar"), "--create", "--file", jar, "-C", classes, "deepjs"])
    with zipfile.ZipFile(jar) as zf:
        names = zf.namelist()
    foreign = [n for n in names if n.endswith(".class") and not n.startswith(("deepjs/burp/", "deepjs/engine/"))]
    if foreign:
        sys.exit(f"build: the jar contains classes that are not ours: {foreign[:3]} …")
    if "deepjs/engine/Engine.class" not in names or "deepjs/burp/DeepJsExtension.class" not in names:
        sys.exit("build: the jar is incomplete")
    print(f"  built {jar} ({os.path.getsize(jar) // 1024} KB)")

    if args.test:
        tests = sorted(glob.glob(os.path.join(ROOT, "src", "test", "java", "deepjs", "burp", "*.java")))
        cp = os.pathsep.join([classes, api])
        run([tool("javac"), "--release", "17", "-encoding", "UTF-8", "-implicit:none", "-cp", cp, "-d", test_classes, *tests])
        cp = os.pathsep.join([classes, test_classes, api])
        run([tool("java"), "-Djava.awt.headless=true", "-cp", cp, "deepjs.burp.Harness"], cwd=out)
        if args.engine:
            run([sys.executable, os.path.join(HERE, "parity.py"), "--classpath", jar, "--engine", os.path.abspath(args.engine)])
    return 0


if __name__ == "__main__":
    sys.exit(main())
