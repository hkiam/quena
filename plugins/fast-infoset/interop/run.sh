#!/bin/sh
# Regenerate the interop corpus with the Java reference implementation
# (test environment only) and compare Piper's decoder against it.
set -e
cd "$(dirname "$0")"
V=2.1.1
JAR=${FI_JAR:-$HOME/.m2/repository/com/sun/xml/fastinfoset/FastInfoset/$V/FastInfoset-$V.jar}
[ -f "$JAR" ] || mvn -q dependency:get -Dartifact=com.sun.xml.fastinfoset:FastInfoset:$V
python3 gen_xml.py
mkdir -p corpus build
javac -cp "$JAR" -d build Gen.java
java -cp "$JAR:build" Gen .
cd ..
RUSTC="$(rustup which --toolchain stable rustc)" "$(rustup which --toolchain stable cargo)" build --quiet --release --example fi2xml
python3 interop/check.py target/release/examples/fi2xml
