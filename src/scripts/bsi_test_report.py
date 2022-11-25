#!/usr/bin/env python3

import sys
import os
import glob
import argparse
import re
from itertools import chain
from functools import reduce
from datetime import datetime, date

import junitparser


def parse_version_file(version_path):
    key_and_val = re.compile(r"^([a-z_]*) = (?:'([^']*)'|([a-zA-Z0-9:\-]+))$")

    results = {}
    with open(version_path, encoding='utf-8') as version_file:
        for line in version_file.readlines():
            match = key_and_val.match(line)
            if not match:
                continue

            key = match.group(1)
            strval = match.group(2)
            intval = match.group(3)
            assert (strval == None) ^ (intval == None)

            if strval is not None:
                results[key] = strval
            elif intval == 'None':
                results[key] = None
            else:
                results[key] = int(intval)

    return results


def get_botan_version_string():
    kv = parse_version_file(os.path.join(
        os.path.dirname(__file__), '../build-data/version.txt'))
    return '%d.%d.%d%s' % (kv['release_major'], kv['release_minor'], kv['release_patch'], kv['release_suffix'])


def apply_template_variables(template, vars):
    value_pattern = re.compile(r'%{([a-z][a-z_0-9]+)}')

    def insert_value(match):
        v = match.group(1)
        if v in vars:
            return str(vars[v])
        raise KeyError(v)
    return value_pattern.sub(insert_value, template)


class Testsuites(junitparser.JUnitXml):
    ''' We override the libary's root element to support
        properties in the 'Testsuites' XML root.'''

    def properties(self):
        """Iterates through all properties."""
        props = self.child(junitparser.Properties)
        if props is None:
            return
        for prop in props:
            yield prop

    def get_property(self, key):
        for p in self.properties():
            if p.name == key:
                return p.value
        raise LookupError("property did not exist")

    @property
    def platform(self):
        known_platforms = {'linux': 'Linux', 'osx': 'macOS',
                           'windows': 'Windows', 'freebsd': 'FreeBSD'}
        osstr = self.get_property("os")
        return known_platforms[osstr] if osstr in known_platforms else 'Unknown System'

    @property
    def os(self):
        return self.get_property('os_name')

    @property
    def os_version(self):
        return self.get_property('os_version')

    @property
    def compiler(self):
        return self.get_property('compiler')

    @property
    def compiler_version(self):
        return self.get_property('compiler_version')

    @property
    def test_command(self):
        return self.get_property('command')

    @property
    def configure_command(self):
        return self.get_property('build_configuration')

    @property
    def architecture(self):
        return self.get_property('architecture')

    @property
    def build_target(self):
        return self.get_property('ci_target')

    @property
    def timestamp(self):
        # Timestamp is in fully qualified ISO format (potentially with) time zone offset.
        # Python supports this only from 3.11
        #
        # See: https://docs.python.org/3/library/datetime.html#datetime.date.fromisoformat
        if sys.version_info >= (3, 11):
            return datetime.fromisoformat(self.get_property('timestamp'))
        elif sys.version_info >= (3, 7):
            return datetime.fromisoformat(self.get_property('timestamp')[:10])
        else:
            raise RuntimeError("Python is too old to read ISO timestamp")

    @property
    def assertions(self):
        asserts = map(lambda x: int(
            x._elem.attrib['assertions']), chain.from_iterable(self))
        return sum(asserts)

    def _format_command(self, command):
        cmd = command.replace('\\', '/').split(' --')

        def irrelevant_params(param):
            filtered_params = ['prefix', 'report-properties',
                               'with-external-includedir', 'test-results-dir']
            for p in filtered_params:
                if param.startswith(p):
                    return False
            return True
        return '\n --'.join(filter(irrelevant_params, cmd))

    def _escape_multiline_string(self, content, indentation_depth=0):
        if '\n' not in content:
            return content
        first_line = True
        out = []
        for line in content.split('\n'):
            if first_line:
                out.append('| %s' % line)
                first_line = False
            else:
                out.append('%s| %s' % (' ' * indentation_depth, line))
        return '\n'.join(out)

    def render(self):
        rst = '\n'.join([
            '.. list-table:: %s %s %s' % (self.os,
                                          self.compiler, self.build_target),
            '  :widths: 20 80',
            '  :header-rows: 0'])
        rst += '\n\n'

        contents = {'Build Name': self.build_target,
                    'Build Config': self._format_command(self.configure_command),
                    'Test Execution': self._format_command(self.test_command),
                    'Date': self.timestamp.date(),
                    'System': self.os,
                    'OS Version': self.os_version,
                    'Compiler': self.compiler + ' ' + self.compiler_version,
                    'Architecture': self.architecture,
                    'Tests Executed': '%d (%d assertions)' % (self.tests, self.assertions),
                    'Tests Passed': self.tests - self.failures - self.skipped,
                    'Tests Failed': self.failures,
                    'Tests Skipped': self.skipped}

        for title, content in contents.items():
            str_content = str(content)
            rst += '  * - %s\n    - %s\n' % (
                title, self._escape_multiline_string(str_content, 6))
        return rst


class Report:
    def __init__(self, report_files, args):
        self._prepare_preamble(args)
        self.reports = [Testsuites.fromfile(report) for report in report_files]
        self.reports.sort(key=lambda x: x.platform +
                          x.os_version, reverse=True)

    def _headline(self, content, level=1):
        if level in [1, 2]:
            line = '='
        elif level == 3:
            line = '-'
        else:
            raise ValueError("Headline level 1-3 are supported only")

        line = line * len(content)
        if level == 1:
            return '\n'.join([line, content, line, ''])
        else:
            return '\n'.join([content, line, ''])

    def _pagebreak(self):
        return '\n'.join(['.. raw:: latex',
                          '',
                          '   \pagebreak',
                          ''])

    def _prepare_preamble(self, args):
        if args.preamble:
            with open(args.preamble) as f:
                self.preamble = f.read()
        else:
            self.preamble = self._headline("Botan Test Report")

        self.preamble = apply_template_variables(self.preamble, {
            'botan_version': get_botan_version_string(),
            'botan_git_sha': args.git_refsha or 'Unknown',
            'botan_git_ref': args.git_refname or 'Unknown',
            'date_today':    date.today()
        })

    def _render_rst(self):
        current_chapter = ""
        out = [self.preamble]
        for report in self.reports:
            if current_chapter != report.platform:
                current_chapter = report.platform
                out.append(self._headline(current_chapter, level=3))
            out.append(report.render())
            out.append(self._pagebreak())
        return '\n\n'.join(out)

    def render(self, outfile, format):
        if format == 'pdf':
            from pypandoc import convert_text
            convert_text(self._render_rst().encode('utf-8'), 'pdf',
                         format='rst', outputfile=outfile)
        elif format == 'rst':
            with open(outfile, 'w+') as f:
                f.write(self._render_rst())
        else:
            raise ValueError("unknown output format: " + format)


def main():
    parser = argparse.ArgumentParser(
        prog='BSI Test Result Generator',
        description='This takes a bunch of JUnit test results and generates a summary document from them.')

    parser.add_argument('reportsdir',
                        help='Directory where junit reports are stored. All *.xml files will be picked up.')
    parser.add_argument('reportfile',
                        help='Output file to be generated')
    parser.add_argument('--format', choices=['pdf', 'rst'], default='rst',
                        help='Output format of the report file')
    parser.add_argument('--preamble', default=None,
                        help='Input file containing reStructuredText that should be added before the generated report')
    parser.add_argument('--git-refname', default=None,
                        help='Reference string to identify the respective source revision (e.g. tag or branch name)')
    parser.add_argument('--git-refsha', default=None,
                        help='Reference commit SHA to identify the respective source revision')

    args = parser.parse_args()

    if not os.path.isdir(args.reportsdir):
        raise Exception("Cannot read junit files from given reports directory")
 
    report_files = glob.glob(os.path.join(args.reportsdir, "*.xml"))
    if not report_files:
        raise Exception("Did not find any junit reports")

    report = Report(report_files, args)
    report.render(args.reportfile, format=args.format)

    return 0


if __name__ == '__main__':
    sys.exit(main())
