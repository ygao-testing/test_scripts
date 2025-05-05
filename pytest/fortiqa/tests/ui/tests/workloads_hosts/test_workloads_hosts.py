"""Workloads Hosts tests"""


def test_verify_workloads_hosts(ui):
    """
    Test Verify workloads hosts
    Oriole Test Cases:
        General
        1203571 Open 'Workloads Hosts' page from the left menu
        1203572 Direct to the correct URL when clicking the left menu
        1203573 Left menu item should be active and highlighted when on the specified page
        Applications
        1204120 Show correct lists of Alerts
        1204121 Show correct lists of List of applications
        1204122 Show correct lists of Active listening ports
        1204123 Show correct lists of Executable versions
        1204124 Show correct lists of Command line by executable
        1204125 Show correct lists of Applications information
        1204126 Show correct lists of List of active containers
        1204127 Show correct lists of List of Container image information
        Files
        1204128 Show correct lists of Alerts
        1204129 Show correct lists of List of changed files
        1204130 Show correct lists of New files
        1204131 Show correct lists of New registry autoruns
        1204132 Show correct lists of Known malicious files
        1204133 Show correct lists of Application details from bad files
        1204134 Show correct lists of Command line by file
        1204135 Show correct lists of List of Package installed executables
        1204136 Show correct lists of List of Non-Package installed executables
        1204137 Show correct lists of List of Executable versions with multiple hashes
        1204138 Show correct lists of List of File hash summary
        Machines
        1204246 Show correct lists of Alerts
        1204247 Show correct lists of Machine properties
        1204248 Show correct lists of Machine tag summary
        1204249 Show correct lists of Machine activity
        1204250 Show correct lists of List of external facing server machines
        1204251 Show correct lists of TCP - client machines making external connections
        1204252 Show correct lists of UDP - client machines making external connections
        1204253 Show correct lists of User login activity
        1204254 Show correct lists of User authentication summary
        1204255 Show correct lists of Exposed ports
        1204256 Show correct lists of Domain lookups by machine
        1204257 Show correct lists of Dropped packets summary
        1204258 Show correct lists of List of active executables
        1204259 Show correct lists of Executable information
        1204260 Show correct lists of List of active containers
        1204261 Show correct lists of Container image information
        1204262 Show correct lists of List of detected secrets
        Networks
        1204263 Show correct lists of Alerts
        1204264 Show correct lists of Domain lookups
        1204265 Show correct lists of Exposed ports
        1204266 Show correct lists of Machine properties
        1204267 Show correct lists of User properties
        1204268 Show correct lists of Server ports with no connection
        1204269 Show correct lists of List of external facing server machines
        1204270 Show correct lists of Client machines making external connections
        1204271 Show correct lists of TCP - client machines making external connections
        1204272 Show correct lists of UDP - client machines making external connections
        1204273 Show correct lists of External UDP connections
        1204274 Show correct lists of IP address summary
        1204275 Show correct lists of DNS summary
        1204276 Show correct lists of Resolved IP information
        Processes
        1204278 Show correct lists of Alerts
        1204279 Show correct lists of Unique process details
        1204280 Show correct lists of List of applications
        1204281 Show correct lists of Exposed ports
        1204282 Show correct lists of Executable versions
        1204283 Show correct lists of Command line by executable
        1204284 Show correct lists of Applications information
        1204285 Show correct lists of TCP - external client connection details
        1204286 Show correct lists of UDP - external client connection details
        1204287 Show correct lists of TCP - internal process connection details
        1204288 Show correct lists of UDP - internal process connection details
        1204289 Show correct lists of TCP - internal connection details from internal devices without agents
        1204290 Show correct lists of UDP - internal connection details from internal devices without agents
        1204291 Show correct lists of TCP - internal connection to internal devices without agents
        1204292 Show correct lists of UDP - internal connection to internal devices without agents
        1204293 Show correct lists of TCP - external server connection details
        1204294 Show correct lists of UDP - external server connection details
        Users
        1204295 Show correct lists of Alerts
        1204296 Show correct lists of User properties
        1204297 Show correct lists of User login activity
        1204298 Show correct lists of User authentication summary
        1204299 Show correct lists of Machine properties
        1204300 Show correct lists of User root action
    """
    ui.workloads_hosts.verify_workloads_hosts_page()
