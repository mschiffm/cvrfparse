#!/usr/bin/env python
"""Parse/Validate a CVRF file and emit user-specified fields. Requires lxml.
"""

__author__ = "Mike Schiffman"
__email__ = "mschiffm@cisco.com"
__credits__ = "William McVey"
__date__ = "February 2013"
__revision__ = "0.9b"
__maintainer__ = "Mike Schiffman"

import os
import sys
import copy
import urllib2
import argparse
from lxml import etree


class CVRF_Syntax(object):
    """
    All of the CVRF Elements and Namespaces are kept here.  As CVRF evolves, make appropriate changes here.
    """
    NAMESPACES = {x.upper(): "{http://www.icasi.org/CVRF/schema/%s/1.1}" % x for x in ("cvrf", "vuln", "prod")}
    CVRF_ARGS = ["all", "DocumentTitle", "DocumentType", "DocumentPublisher", "DocumentTracking", "DocumentNotes",
                 "DocumentDistribution", "AggregateSeverity", "DocumentReferences", "Acknowledgments"]
    VULN_ARGS = ["all", "Title", "ID", "Notes", "DiscoveryDate", "ReleaseDate", "Involvements", "CVE", "CWE",
                 "ProductStatuses", "Threats", "CVSSScoreSets", "Remediations", "References", "Acknowledgments"]
    PROD_ARGS = ["all", "Branch", "FullProductName", "Relationship", "ProductGroups"]
    CVRF_SCHEMA = "http://www.icasi.org/CVRF/schema/cvrf/1.1/cvrf.xsd"
    CVRF_CATALOG = "./cvrfparse/schemata/catalog.xml"


class PrependerAction(argparse.Action):
    """
    Customization for argparse. Prepends some static text to an accumalated list.
    """
    prepend_text = ""
    def __call__(self, parser, namespace, values, option_string=None):
        orig = getattr(namespace, self.dest, None)
        items = [] if orig is None else copy.copy(orig)
        for value in values:
            items.append(self.prepend_text + value)
        setattr(namespace, self.dest, items)


class NonDupBracketFormatter(argparse.HelpFormatter):
    """
    Customization for argparse. A formatter that is a more terse in repeated arguments.
    """
    def _format_args(self, action, default_metavar):
        get_metavar = self._metavar_formatter(action, default_metavar)
        if action.nargs == argparse.ZERO_OR_MORE:
            result = "[%s ...]" % get_metavar(1)
        elif action.nargs == argparse.ONE_OR_MORE:
            result = "%s [...]" % get_metavar(1)
        else:
            result = super(NonDupBracketFormatter, self)._format_args(
                action, default_metavar)
        return result


def namespace_prepend(namespace):
    """
    Returns a dynamic class (not instance) with appropriate prepend_text.
    """
    return type("Prepend_%s" % namespace, (PrependerAction,),
                {"prepend_text": CVRF_Syntax.NAMESPACES[namespace]})


def chop_ns_prefix(element):
    """
    Return the element of a fully qualified namespace URI

    element: a fully qualified ET element tag
    """
    return element[element.rindex("}") + 1:]


def print_node(node, strip_ns, f=sys.stdout):
    """
    Print each XML node

    node: the ElementTree node to be printed
    strip_ns: boolean that when true indicates the namespace prefix will be chomped
    f: the file to print to (default is stdout)
    """
    if node.tag:
        print >> f, "[%s]" %(chop_ns_prefix(node.tag) if strip_ns else node.tag),
    if node.text:
        print >> f, node.text.strip()
    if node.attrib:
        for key in node.attrib:
            print >> f, "(%s: %s)" %(key, node.attrib[key])
        print >> f


def cvrf_validate(f, cvrf_doc):
    """
    Validates a CVRF document

    f: file object containing the schema
    cvrf_doc: the serialized CVRF ElementTree object
    returns: a code (True for valid / False for invalid) and a reason for the code
    """
    try:
        xmlschema_doc = etree.parse(f)
    except etree.XMLSyntaxError as e:
        log = e.error_log.filter_from_level(etree.ErrorLevels.FATAL)
        return False, "Parsing error, schema document \"{0}\" is not well-formed: {1}".format(f.name, log)
    xmlschema = etree.XMLSchema(xmlschema_doc)

    try:
        xmlschema.assertValid(cvrf_doc)
        return True, "Valid"
    except etree.DocumentInvalid:
        return False, xmlschema.error_log


def cvrf_dump(results, strip_ns):
    """
    Iterates over results and dumps to the dictionary key (which is a file handle)

    results: a dictionary of the format: {filename, [ElementTree node, ...], ...}
    strip_ns: boolean that when true indicates the namespace prefix will be chomped
    """
    for key in results:
        if key == "stdout":
            f = sys.stdout
        else:
            try:
                f = open(key, "w")
            except IOError as e:
                sys.exit("{0}: I/O error({1}) \"{2}\": {3}".format(progname, e.errno, key, e.strerror))
        for item in results[key]:
            print_node(item, strip_ns, f)
        f.close()

def cvrf_dispatch(cvrf_doc, parsables, collate_vuln, strip_ns):
    """
    Filter through a CVRF document and perform user-specified actions and report the results

    cvrf_doc: the serialized CVRF ElementTree object
    collate_vuln: boolean indicating whether or not to collate the vulnerabilities
    strip_ns: boolean that when true indicates the namespace prefix will be chomped
    returns: N/A
    """
    if parsables:
        results = cvrf_parse(cvrf_doc, parsables)
        cvrf_dump(results, strip_ns)
    if collate_vuln:
        results = cvrf_collate_vuln(cvrf_doc)
        cvrf_dump(results, strip_ns)


def cvrf_parse(cvrf_doc, parsables):
    """
    Parse a cvrf_doc and return a list of elements as determined by parsables

    cvrf_doc: the serialized CVRF ElementTree object
    parsables: list of elements to parse from a CVRF doc
    returns: a dictionary of the format {filename:[item, ...]}
    """
    items = []
    for element in parsables:
        for node in cvrf_doc.iter(element):
            for child in node.iter():
                items.append(child)
    # Hardcoded output for now, eventually make this user-tunable
    return {"stdout": items}


def cvrf_collate_vuln(cvrf_doc):
    """
    Zip through a cvrf_doc and return all vulnerability elements collated by ordinal

    cvrf_doc: the serialized CVRF ElementTree object
    returns: a dictionary of the format {filename:[item, ...], filename:[item, ...]}
    """
    results = {}
    # Obtain document title to use in the filename(s) tiptoeing around around the curly braces in our NS definition
    document_title = cvrf_doc.findtext("cvrf:DocumentTitle",
                                       namespaces={"cvrf": CVRF_Syntax.NAMESPACES["CVRF"].replace("{", "").replace("}", "")}).strip().replace(" ", "_")

    # Constrain Xpath search to the Vulnerability container
    for node in cvrf_doc.findall(".//" + CVRF_Syntax.NAMESPACES["VULN"] + "Vulnerability"):
        # Create filename based on ordinal number to use as a key for results dictionary
        filename = "cvrfparse-" + document_title + "-ordinal-" + node.attrib["Ordinal"] + ".txt"
        # Create an iterator to iterate over each child element and populate results dictionary values
        results[filename] = node.iter()

    return results


def post_process_arglist(arg, namespace, valid_args):
    parsables = []

    if CVRF_Syntax.NAMESPACES[namespace] + "all" in arg:
        for element in valid_args:
            parsables.append(CVRF_Syntax.NAMESPACES[namespace] + element)
        parsables.remove(CVRF_Syntax.NAMESPACES[namespace] + "all")
    else:
        for element in arg:
            parsables.append(element)

    return parsables


def main(progname):
    parser = argparse.ArgumentParser(formatter_class=NonDupBracketFormatter,
                                     description="Validate/parse a CVRF 1.1 document and emit user-specified bits.")
    parser.add_argument("-f", "--file", required="True", action="store",
                        help="candidate CVRF 1.1 XML file")
    parser.add_argument('--cvrf', nargs="*", choices=CVRF_Syntax.CVRF_ARGS,
                        action=namespace_prepend("CVRF"),
                        help="emit CVRF elements, use \"all\" to glob all CVRF elements.")
    parser.add_argument("--vuln", nargs="*", choices=CVRF_Syntax.VULN_ARGS,
                        action=namespace_prepend("VULN"),
                        help="emit Vulnerability elements, use \"all\" to glob all Vulnerability elements.")
    parser.add_argument("--prod", nargs="*", choices=CVRF_Syntax.PROD_ARGS,
                        action=namespace_prepend("PROD"),
                        help="emit ProductTree elements, use \"all\" to glob all ProductTree elements.")
    parser.add_argument("-c", "--collate", dest="collate_vuln", default=False,
                        action="store_true",
                        help="collate all of the Vulnerability elements by ordinal into separate files")
    parser.add_argument("-s", "--strip-ns", dest="strip_ns", default=False, action="store_true",
                        help="strip namespace header from element tags before printing")
    parser.add_argument("-V", "--validate", default=False, action="store_true",
                        help="validate the CVRF document")
    parser.add_argument("-S", "--schema", action="store",
                        help="specify local alternative for cvrf.xsd")
    parser.add_argument("-C", "--catalog", action="store",
                        help="specify location for catalog.xml (default is {0})".format(CVRF_Syntax.CVRF_CATALOG))
    parser.add_argument("-v", "--version", action="version", version="%(prog)s " + __revision__)

    args = parser.parse_args()

    # Post process argument lists into a single list, handling 'all' globs if present
    # this block should probably eventually be folded into argparse
    parsables = []
    if args.cvrf:
        parsables.extend(post_process_arglist(args.cvrf, "CVRF", CVRF_Syntax.CVRF_ARGS))
    if args.vuln:
        parsables.extend(post_process_arglist(args.vuln, "VULN", CVRF_Syntax.VULN_ARGS))
    if args.prod:
        parsables.extend(post_process_arglist(args.prod, "PROD", CVRF_Syntax.PROD_ARGS))

    # First things first: parse the document (to ensure it is well-formed XML) to obtain an ElementTree object
    # to pass to the CVRF validator/parser
    try:
        cvrf_doc = etree.parse(args.file)
    except IOError:
        sys.exit("{0}: I/O error: \"{1}\" does not exist".format(progname, args.file))
    except etree.XMLSyntaxError as e:
        sys.exit("{0}: Parsing error, document \"{1}\" is not well-formed: {2}".format(progname, args.file, e.error_log.filter_from_level(etree.ErrorLevels.FATAL)))

    if args.validate is True:
        try:
            if args.schema:
                # Try to use local schema files
                f = open(args.schema, 'r')
                # If the supplied file is not a valid catalog.xml or doesn't exist lxml will fall back to
                # using remote validation
                catalog = args.catalog if args.catalog else CVRF_Syntax.CVRF_CATALOG
                os.environ.update(XML_CATALOG_FILES=catalog)
            else:
                print >> sys.stderr, "Fetching schemata..."
                f = urllib2.urlopen(CVRF_Syntax.CVRF_SCHEMA)
        except IOError as e:
            sys.exit("{0}: I/O error({1}) \"{2}\": {3}".format(progname, e.errno, args.schema, e.strerror))

        (code, result) = cvrf_validate(f, cvrf_doc)
        f.close()
        if code is False:
            sys.exit("{0}: {1}".format(progname, result))
        else:
            print >> sys.stderr, result

    cvrf_dispatch(cvrf_doc, parsables, collate_vuln=args.collate_vuln, strip_ns=args.strip_ns)

if __name__ == "__main__":
    progname=os.path.basename(sys.argv[0])
    try:
        main(progname)
    except Exception, value:
        (exc_type, exc_value, exc_tb) = sys.exc_info()
        sys.excepthook(exc_type, exc_value, exc_tb)     # if debugging
        sys.exit("%s: %s: %s" % (progname, exc_type.__name__, exc_value))
    sys.exit(0)
