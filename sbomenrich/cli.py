# Copyright (C) 2026 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import argparse
import os
import platform
import sys
import textwrap
from collections import ChainMap

from sbomenrich.version import VERSION
from sbomenrich.enricher import SBOMEnricher

# CLI processing


def main(argv=None):

    argv = argv or sys.argv
    app_name = "sbomenrich"
    parser = argparse.ArgumentParser(
        prog=app_name,
        description=textwrap.dedent("""
            Sbomenrich updates a Software Bill of Materials by amending the attributes for components
            """),
    )
    input_group = parser.add_argument_group("Input")
    input_group.add_argument(
        "-i",
        "--input-file",
        action="store",
        default="",
        help="filename of SBOM",
    )
    input_group.add_argument(
        "--enrich",
        action="store",
        default="",
        help="filename containing enrichment data",
    )
    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-d",
        "--debug",
        action="store_true",
        default=False,
        help="add debug information",
    )
    output_group.add_argument(
        "--sbom",
        action="store",
        default="cyclonedx",
        choices=["spdx", "cyclonedx"],
        help="specify type of sbom to generate (default: cyclonedx)",
    )
    output_group.add_argument(
        "--format",
        action="store",
        default="json",
        choices=["tag", "json", "yaml"],
        help="specify format of software bill of materials (sbom) (default: json)",
    )

    output_group.add_argument(
        "-o",
        "--output-file",
        action="store",
        default="",
        help="output filename (default: output to stdout)",
    )

    parser.add_argument("-V", "--version", action="version", version=VERSION)

    defaults = {
        "inout_file": "",
        "enrich": "",
        "output_file": "",
        "sbom": "cyclonedx",
        "debug": False,
        "format": "json",
    }

    raw_args = parser.parse_args(argv[1:])
    args = {key: value for key, value in vars(raw_args).items() if value}
    args = ChainMap(args, defaults)

    # Validate CLI parameters

    sbom_name = args["input_file"]
    enrich_file = args["enrich"]

    # Must gave both a SBOM and an enrichment file
    if sbom_name == "" or enrich_file == "":
        print ("[ERROR] Must specify a SBOM and enrichment file")
        sys.exit(1)

    # Check the SBOM and enrichment file exist
    if not os.path.exists(sbom_name) or os.path.getsize(sbom_name) == 0:
        print(f"[ERROR] SBOM file {sbom_name} not found or empty")
        sys.exit(1)

    if not os.path.exists(enrich_file) or os.path.getsize(enrich_file) == 0:
        print(f"[ERROR] Enrichment file {enrich_file} not found or empty")
        sys.exit(1)

    # Ensure format is aligned with type of SBOM
    bom_format = args["format"]
    if args["sbom"] == "cyclonedx":
        # Only JSON format valid for CycloneDX
        if bom_format != "json":
            bom_format = "json"

    if args["debug"]:
        print("SBOM file:", args["input_file"])
        print("Enrichment file", args["enrich"])
        print("SBOM type:", args["sbom"])
        print("Format:", bom_format)
        print("Output file:", args["output_file"])

    sbom_enricher = SBOMEnricher(enrich_file=args["enrich"], debug=args["debug"])
    sbom_enricher.process_SBOM(sbom_file=args["input_file"])
    sbom_enricher.generate_enriched_SBOM(sbom_file=args['output_file'], format=bom_format)
    return 0


if __name__ == "__main__":
    sys.exit(main())
