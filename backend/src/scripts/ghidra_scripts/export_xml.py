# Export Ghidra project to XML with all annotations
# @category: Export

import sys
from ghidra.app.util.exporter import XmlExporter
from ghidra.util.task import TaskMonitor
from java.io import File

# Get output path from command line
output_path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/export.xml"

# Create exporter
exporter = XmlExporter()

# Set options to include annotations but exclude binary content
options = exporter.getOptions(lambda x: None)

# Set export file
output_file = File(output_path)

# Export with current program
monitor = TaskMonitor.DUMMY
success = exporter.export(output_file, currentProgram, None, monitor)

if success:
    print("SUCCESS: Exported to {}".format(output_path))
else:
    print("ERROR: Export failed")
    sys.exit(1)
