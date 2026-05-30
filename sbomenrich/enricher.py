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

    def __init__(self, enrich_file, debug):
        self.enrich_data = None
        self.debug = debug
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
            # Check that the package name exists
            if enriched_package.get(thepackage.get_name()) is not None:
                # Enrich package metadata
                for key, value in enriched_package.get(thepackage.get_name()).items():
                    if key != 'name':
                        if self.debug:
                            print (f"[ENRICH] {thepackage.get_name()}. Attribute {key}, Value {value}")
                        if key == 'purl':
                            thepackage.set_purl(value)
                        elif key == 'checksum':
                            thepackage.set_checksum("SHA512", value)
                        elif key != 'property':
                            thepackage.set_value(key, value)
                        else:
                            property_key, property_value = value.split('#')
                            thepackage.set_property(property_key, property_value)
            self.new_packages[
                (thepackage.get_name(), thepackage.get_value("version"))
            ] = thepackage.get_package()

    def generate_enriched_SBOM(self, sbom_file=None, format=None):
        if format is None:
            format = self.sbom_parser.get_format()
        app_name="SBOMenrich"
        enriched_sbom = SBOM()
        enriched_sbom.set_type(sbom_type=self.sbom_parser.get_type())
        enriched_sbom.add_document(self.sbom_parser.get_document())
        enriched_sbom.add_files(self.sbom_parser.get_files())
        enriched_sbom.add_packages(self.new_packages)
        enriched_sbom.add_relationships(self.sbom_parser.get_relationships())
        enriched_generator = SBOMGenerator(False, sbom_type=self.sbom_parser.get_type(), format=format, application=app_name, version=VERSION)
        # TODO set SBOM Application name
        enriched_generator.generate("TestApp", sbom_data= enriched_sbom.get_sbom(), filename=sbom_file)