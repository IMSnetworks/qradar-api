# qradar-api
I developped this Python library to interfact with QRadar REST API using pandas. Most methods return a DataFrame.
To use it, pass a path to a security token to the constructor for authentication.

There are some methods I use for reporting: getTimeSeries, runQuery, getAllOffenses. By default, those methods will cache the result in a csv file and return the content of the file if they are ran again with the same parameters. That makes them convenient to use when building a report in a jupyter notebook.
getNetwork is also used for reporting to add some context information for an IP. It will start by searching for the IP in the network hierarchy if it has been initialized with initNetworks and will fallback to reverseDNS and whoIS if it doesn't find it.

Other methods are used to manipulate reference sets, maps and map of sets : CreateRefSet, GetRefSet, SyncRefSet, ...

getNetworks returns the network hierarchy for a domain. setNetworks changes the whole network hierarchy with the json passed as a parameter.