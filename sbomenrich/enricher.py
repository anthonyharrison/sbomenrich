# Copyright (C) 2026 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

from sbomenrich.version import VERSION
import yaml

from lib4sbom.generator import SBOMGenerator
from lib4sbom.output import SBOMOutput
from lib4sbom.parser import SBOMParser
from lib4sbom.data.package import SBOMPackage
from lib4sbom.sbom import SBOM

class SBOMEnricher:

    def __init__(self, enrich_file):
        self.enrich_data = None
        with open(enrich_file, 'r') as f:
            self.enrich_data = yaml.safe_load(f)

    def process_SBOM(self, sbom_file):
        # Read SBOM
        self.sbom_parser = SBOMParser()
        # Load SBOM - will autodetect SBOM type
        self.sbom_parser.parse_file(sbom_file)
        enriched_package = {}
        for package in self.enrich_data.get('packages',[]):
            enriched_package[package.get('name')] = package
        thepackage = SBOMPackage()
        self.new_packages = {}
        for package in self.sbom_parser.get_packages():
            thepackage.initialise()
            thepackage.copy_package(package)
            if enriched_package.get(thepackage.get_name()) is not None:
                # Enrich package metadata
                for key, value in enriched_package.get(thepackage.get_name()).items():
                    if key != 'name':
                        if key != 'property':
                            thepackage.set_value(key, value)
                        else:
                            property_key, property_value = value.split('#')
                            thepackage.set_property(property_key, property_value)
            self.new_packages[
                (thepackage.get_name(), thepackage.get_value("version"))
            ] = thepackage.get_package()

    def generate_enriched_SBOM(self, sbom_file=None):
        enriched_sbom = SBOM()
        enriched_sbom.set_type(sbom_type=self.sbom_parser.get_type())
        enriched_sbom.add_document(self.sbom_parser.get_document())
        enriched_sbom.add_packages(self.new_packages)
        enriched_sbom.add_relationships(self.sbom_parser.get_relationships())
        enriched_generator = SBOMGenerator(False, sbom_type=self.sbom_parser.get_type(), format=self.sbom_parser.get_format())
        # TODO set SBOM file name
        enriched_generator.generate("TestApp", enriched_sbom.get_sbom())