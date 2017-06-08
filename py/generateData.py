import subprocess
import re
import json

# ----- ----- helpers ----- -----

def printColor(text):
	print("\033[0;33m%s\033[0m" % text)
	return 0

# ----- ----- data ----- -----

def persistData(jsonData, jsonFileName, action):
	if action == "load":
		printColor("data")
		try:
			printColor("    load")
			jsonFileHandle = open(jsonFileName, "r")
			jsonData = json.load(jsonFileHandle)
			jsonFileHandle.close()
		# except FileNotFoundError (works only from pyton3 onwards)
		except IOError:
			printColor("    no file")
			pass
		printColor("done")
	else:
		jsonFileHandle = open(jsonFileName, "w")
		json.dump(jsonData, jsonFileHandle, indent=4)
		jsonFileHandle.close()
	return jsonData

# ----- ----- network ----- -----

def getInterfaces(jsonData):
	printColor("interfaces")

	interfaces = []
	for interface in jsonData["data"]["interfaces"]["values"]:
		if interface["name"] not in interfaces:
			interfaces.append(interface["name"])

	regexMacAddress = "((?:[0-9A-Fa-f]{2}\:){5}[0-9A-Fa-f]{2})"
	regexIpv4Address = "((?:[0-9]{1,3}\.){3}[0-9]{1,3})"
	regexStringInterface = re.compile("(.+)\: flags=")
	regexStringMacAddress = re.compile("[\t ]+ether %s" % regexMacAddress)
	regexStringIpv4Address = re.compile("[\t ]+inet %s" % regexIpv4Address)

	command = ['sudo', 'ifconfig']
	printColor("    %s" % " ".join(command))
	ifconfig = subprocess.Popen(command, stdout=subprocess.PIPE)
	jsonData["data"]["interfaces"]["origin"] = " ".join(command)
	lineId = 0
	for line in iter(ifconfig.stdout.readline, b""):
		line = line.rstrip()
		regexMatch = re.match(regexStringInterface, line)
		if regexMatch is not None:
			if regexMatch.group(1) in interfaces: continue # to do !!
			lineId += 1
			jsonData["data"]["interfaces"]["values"].append({ "id": lineId, "name": regexMatch.group(1) })
			continue
		regexMatch = re.match(regexStringMacAddress, line)
		if regexMatch is not None:
			jsonData["data"]["interfaces"]["values"][len(jsonData["data"]["interfaces"]["values"]) - 1]["macAddr"] = regexMatch.group(1).lower()
			continue
		regexMatch = re.match(regexStringIpv4Address, line)
		if regexMatch is not None:
			jsonData["data"]["interfaces"]["values"][len(jsonData["data"]["interfaces"]["values"]) - 1]["ipv4Addr"] = regexMatch.group(1)

	# extract subnet info
	excludedIpv4Addresses = ["127.0.0.1", "0.0.0.0"]
	lineId = 0
	for interface in jsonData["data"]["interfaces"]["values"]:
		if "ipv4Addr" in interface and interface["ipv4Addr"] is not None and interface["ipv4Addr"] not in excludedIpv4Addresses:
			lineId += 1
			jsonData["profiles"]["subnets"]["values"].append({ "id": lineId, "name": ".".join(interface["ipv4Addr"].split(".")[0:3]),
				"interface": interface["name"] })

	printColor("    %s results" % str(len(jsonData["data"]["interfaces"]["values"])))
	printColor("done")
	return 0

def getActivity(jsonData):
	printColor("activity")

	excludedIpv4Addresses = ["127.0.0.1", "0.0.0.0"]
	interface = ""
	for interf in jsonData["data"]["interfaces"]["values"]:
		if "ipv4Addr" in interf and interf["ipv4Addr"] is not None and interf["ipv4Addr"] not in excludedIpv4Addresses:
			interface = interf["name"] # grab the last valid interface
	if interface == "":
		printColor("    no interface")
		printColor("aborted")
		return 0

	regexTimestamp = "((?:[0-9]{2}\:){2}[0-9]{2}\.[0-9]{6})"
	regexMacAddress = "((?:[0-9A-Fa-f]{2}\:){5}[0-9A-Fa-f]{2})"
	regexIpv4 = "((?:[0-9]{1,3}\.){3}[0-9]{1,3})"
	regexPort = "([0-9]{1,5})"
	regexDetails = "(.+)"
	regexIpv6 = ""
	regexStringArpRequest = re.compile("%s %s > %s, ethertype (ARP \(0x0806\)), length [0-9]+\: %s, length" % \
		(regexTimestamp, regexMacAddress, regexMacAddress, regexDetails))
	regexStringArpReply = re.compile("%s %s > %s, ethertype (ARP \(0x0806\)), length [0-9]+\: %s, length" % \
		(regexTimestamp, regexMacAddress, regexMacAddress, regexDetails))
	regexStringEapol = re.compile("%s %s > %s, ethertype (EAPOL \(0x888e\)), length [0-9]+\: %s, len [0-9]+" % \
		(regexTimestamp, regexMacAddress, regexMacAddress, regexDetails))
	regexStringIPv4Igmp = re.compile("%s %s > %s, ethertype (IPv4 \(0x0800\)), length [0-9]+\: %s > %s\: %s" % \
		(regexTimestamp, regexMacAddress, regexMacAddress, regexIpv4, regexIpv4, regexDetails))
	regexStringIPv4 = re.compile("%s %s > %s, ethertype (IPv4 \(0x0800\)), length [0-9]+\: %s.%s > %s.%s\: %s" % \
		(regexTimestamp, regexMacAddress, regexMacAddress, regexIpv4, regexPort, regexIpv4, regexPort, regexDetails))
	regexStringIPv6 = re.compile("%s %s > %s, ethertype (IPv6 \(0x86dd\)), length [0-9]+\: %s" % \
		(regexTimestamp, regexMacAddress, regexMacAddress, regexDetails))

	command = ["tcpdump", "-e", "-n", "-c", "5", "-i", interface]
	printColor("    %s" % " ".join(command))
	tcpdump = subprocess.Popen(command, stdout=subprocess.PIPE)
	jsonData["data"]["activity"]["origin"] = " ".join(command)
	lineId = 0
	for line in iter(tcpdump.stdout.readline, b""):
		lineId += 1
		line = line.rstrip()
		# parse ARP request packets
		regexMatch = re.match(regexStringArpRequest, line)
		if regexMatch is not None:
			jsonData["data"]["activity"]["values"].append({ "id": lineId, "timeStamp": regexMatch.group(1),
				"srcMacAddr": regexMatch.group(2).lower(), "dstMacAddr": regexMatch.group(3).lower(),
				"etherType": regexMatch.group(4), "details": regexMatch.group(5) })
			continue
		# parse ARP reply packets
		regexMatch = re.match(regexStringArpReply, line)
		if regexMatch is not None:
			jsonData["data"]["activity"]["values"].append({ "id": lineId, "timeStamp": regexMatch.group(1),
				"srcMacAddr": regexMatch.group(2).lower(), "dstMacAddr": regexMatch.group(3).lower(),
				"etherType": regexMatch.group(4), "details": regexMatch.group(5) })
			continue
		# parse EAPOL packets
		regexMatch = re.match(regexStringEapol, line)
		if regexMatch is not None:
			jsonData["data"]["activity"]["values"].append({ "id": lineId, "timeStamp": regexMatch.group(1),
				"srcMacAddr": regexMatch.group(2).lower(), "dstMacAddr": regexMatch.group(3).lower(),
				"etherType": regexMatch.group(4), "details": regexMatch.group(5) })
			continue
		# parse IPv4 IGMP packets
		regexMatch = re.match(regexStringIPv4Igmp, line)
		if regexMatch is not None:
			jsonData["data"]["activity"]["values"].append({ "id": lineId, "timeStamp": regexMatch.group(1),
				"srcMacAddr": regexMatch.group(2).lower(), "dstMacAddr": regexMatch.group(3).lower(),
				"etherType": regexMatch.group(4), "srcIpv4Addr": regexMatch.group(5),
#				"dstIpv4Addr": regexMatch.group(6), "details": regexMatch.group(7) })
				"dstIpv4Addr": regexMatch.group(6), "details": line })
			continue
		# parse IPv4 packets
		regexMatch = re.match(regexStringIPv4, line)
		if regexMatch is not None:
			jsonData["data"]["activity"]["values"].append({ "id": lineId, "timeStamp": regexMatch.group(1),
				"srcMacAddr": regexMatch.group(2).lower(), "dstMacAddr": regexMatch.group(3).lower(),
				"etherType": regexMatch.group(4), "srcIpv4Addr": regexMatch.group(5),
				"srcPort": regexMatch.group(6), "dstIpv4Addr": regexMatch.group(7), "dstPort": regexMatch.group(8),
				"details": regexMatch.group(9) })
			if jsonData["data"]["activity"]["values"][-1]["details"].startswith("Flags"):
				jsonData["data"]["activity"]["values"][-1]["details"] = ""
			continue
		# parse IPv6 packets
		regexMatch = re.match(regexStringIPv6, line)
		if regexMatch is not None:
			jsonData["data"]["activity"]["values"].append({ "id": lineId, "timeStamp": regexMatch.group(1),
				"srcMacAddr": regexMatch.group(2).lower(), "dstMacAddr": regexMatch.group(3).lower(),
				"etherType": regexMatch.group(4), "details": regexMatch.group(5) })
			continue
		# catchall
		jsonData["data"]["activity"]["values"].append({ "details": line })

	# ---------- process activity data
	# get hosts
	hosts = []
	for host in jsonData["profiles"]["hosts"]["values"]:
		if host["macAddr"] not in hosts:
			hosts.append(host["macAddr"])
	for packet in jsonData["data"]["activity"]["values"]:
		if "srcMacAddr" in packet and packet["srcMacAddr"] not in hosts:
			jsonData["profiles"]["hosts"]["values"].append({ "macAddr": packet["srcMacAddr"] })
			hosts.append(packet["srcMacAddr"])
		if "dstMacAddr" in packet and packet["dstMacAddr"] not in hosts:
			jsonData["profiles"]["hosts"]["values"].append({ "macAddr": packet["dstMacAddr"] })
			hosts.append(packet["dstMacAddr"])

	# get ip addresses
	for packet in jsonData["data"]["activity"]["values"]:
		if "srcMacAddr" in packet and "srcIpv4Addr" in packet:
			for host in jsonData["profiles"]["hosts"]["values"]:
				if packet["srcMacAddr"] == host["macAddr"] and "ipv4Addr" not in host:
					 host["ipv4Addr"] = packet["srcIpv4Addr"]

	# add any new behavior
#	for host in hosts:
#		found = 0
#		for index, behavior in enumerate(jsonData["behaviors"]["values"]):
#			if behavior["macAddr"] == host:
#				found = 1
#				break
#		if found == 0:
#			jsonData["behaviors"]["values"].append({ "macAddr": host, "ipv4Addr": "", "packetsSent": 0, "packetsRcvd": 0 })
	# count packets related to each host
#	for index, host in enumerate(jsonData["behaviors"]["values"]):
#		jsonData["behaviors"]["values"][index]["packetsSent"] = 0
#		jsonData["behaviors"]["values"][index]["packetsRcvd"] = 0
#		for packet in jsonData["data"]["activity"]["values"]:
#			if "srcMacAddr" in packet and packet["srcMacAddr"] == host["macAddr"]:
#				jsonData["behaviors"]["values"][index]["packetsSent"] += 1
#			if "dstMacAddr" in packet and packet["dstMacAddr"] == host["macAddr"]:
#				jsonData["behaviors"]["values"][index]["packetsRcvd"] += 1
	printColor("    %s results" % str(len(jsonData["data"]["activity"]["values"])))
	printColor("done")
	return 0

def getTraces(jsonData):
	printColor("traces")

	excludedIpv4Addresses = ["127.0.0.1", "0.0.0.0"]
	interface = ""
	for interf in jsonData["data"]["interfaces"]["values"]:
		if "ipv4Addr" in interf and interf["ipv4Addr"] is not None and interf["ipv4Addr"] not in excludedIpv4Addresses:
			interface = interf["name"] # grab the last valid interface
	if interface == "":
		printColor("    no interface")
		printColor("aborted")
		return 0
	hosts = []
	for host in jsonData["profiles"]["hosts"]["values"]:
		if "ipv4Addr" in host and host["ipv4Addr"] is not None:
			if host["ipv4Addr"] not in hosts and host["ipv4Addr"] not in excludedIpv4Addresses:
				hosts.append(host["ipv4Addr"])
	if len(hosts) < 1:
		printColor("    no hosts")
		printColor("aborted")
		return 0

	regexHop = "([0-9]+)"
	regexIpv4 = "((?:[0-9]{1,3}\.){3}[0-9]{1,3})"
	regexLatency = "([0-9]+\.[0-9]{3} ms)"
	regexStringTrace = re.compile("[ ]*%s  %s  %s" % (regexHop, regexIpv4, regexLatency))

	command = ['traceroute', '-n', '-q', '1', '-m', '10', '-i', interface]
	jsonData["data"]["traces"]["origin"] = " ".join(command + ["[host]"])
	lineId = 0
	for host in hosts:
		printColor("    %s" % " ".join(command + [host]))
		trace = subprocess.Popen(command + [host], stdout=subprocess.PIPE)
		for line in iter(trace.stdout.readline, b""):
			lineId += 1
			line = line.rstrip()
			regexMatch = re.match(regexStringTrace, line)
			if regexMatch is not None:
				jsonData["data"]["traces"]["values"].append({ "id": lineId, "host": host, "hop": regexMatch.group(1),
					"ipv4Addr": regexMatch.group(2), "latency": regexMatch.group(3) })

	printColor("    %s results" % str(len(jsonData["data"]["traces"]["values"])))
	printColor("done")
	return 0

def getPings(jsonData):
	printColor("pings")

	excludedIpv4Addresses = ["127.0.0.1", "0.0.0.0"]
	interface = ""
	for interf in jsonData["data"]["interfaces"]["values"]:
		if "ipv4Addr" in interf and interf["ipv4Addr"] is not None and interf["ipv4Addr"] not in excludedIpv4Addresses:
			interface = interf["name"] # grab the last valid interface
	if interface == "":
		printColor("    no interface")
		printColor("aborted")
		return 0

	ownSubnet = ""
	for subnet in jsonData["profiles"]["subnets"]["values"]:
		if subnet["interface"] == interface:
			ownSubnet = subnet["name"]
			break
	if ownSubnet == "":
		printColor("    no subnet")
		printColor("aborted")
		return 0

	regexIpv4Address = "((?:[0-9]{1,3}\.){3}[0-9]{1,3})"
	regexLatency = "([0-9]+\.[0-9]+s)"
	regexMacAddress = "((?:[0-9A-Fa-f]{2}\:){5}[0-9A-Fa-f]{2})"
	regexMacBrand = "(.+)"
	regexStringIpv4Addr = re.compile("Nmap scan report for %s" % regexIpv4Address)
	regexStringLatency = re.compile("Host is up \(%s latency\)" % regexLatency)
	regexStringMacAddr = re.compile("MAC Address\: %s \(%s\)" % (regexMacAddress, regexMacBrand))

	command = ['nmap', '-n', '-sn', '-PS', '-PA', '-PU', '-PY', '-PE', '-PP', '-PM', '-PO', '-PR', '-e', interface, ownSubnet + ".1-254"]
	printColor("    %s" % " ".join(command))
	pings = subprocess.Popen(command, stdout=subprocess.PIPE)
	jsonData["data"]["pings"]["origin"] = " ".join(command)
	lineId = 0
	for line in iter(pings.stdout.readline, b""):
		line = line.rstrip()
		regexMatch = re.match(regexStringIpv4Addr, line)
		if regexMatch is not None:
			lineId += 1
			jsonData["data"]["pings"]["values"].append({ "id": lineId, "ipv4Addr": regexMatch.group(1) })
			continue
		regexMatch = re.match(regexStringLatency, line)
		if regexMatch is not None:
			jsonData["data"]["pings"]["values"][len(jsonData["data"]["pings"]["values"]) - 1]["latency"] = regexMatch.group(1)
			continue
		regexMatch = re.match(regexStringMacAddr, line)
		if regexMatch is not None:
			jsonData["data"]["pings"]["values"][len(jsonData["data"]["pings"]["values"]) - 1]["macAddr"] = regexMatch.group(1).lower()
			jsonData["data"]["pings"]["values"][len(jsonData["data"]["pings"]["values"]) - 1]["macBrand"] = regexMatch.group(2)
			continue

	# extract hosts
	hosts = []
	for host in jsonData["profiles"]["hosts"]["values"]:
		if "ipv4Addr" in host and host["ipv4Addr"] not in hosts:
			hosts.append(host["ipv4Addr"])
	for ping in jsonData["data"]["pings"]["values"]:
		if "ipv4Addr" in ping and ping["ipv4Addr"] not in hosts:
			jsonData["profiles"]["hosts"]["values"].append({ "ipv4Addr": ping["ipv4Addr"] })
			hosts.append(ping["ipv4Addr"])

	printColor("    %s results" % str(len(jsonData["data"]["pings"]["values"])))
	printColor("done")
	return 0

def getPorts(jsonData):
	printColor("ports")
#"nmap -n -Pn -sU --reason %s"

	excludedIpv4Addresses = ["127.0.0.1", "0.0.0.0"]
	interface = ""
	for interf in jsonData["data"]["interfaces"]["values"]:
		if "ipv4Addr" in interf and interf["ipv4Addr"] is not None and interf["ipv4Addr"] not in excludedIpv4Addresses:
			interface = interf["name"] # grab the last valid interface
	if interface == "":
		printColor("    no interface")
		printColor("aborted")
		return 0

	excludedIpv4Addresses = ['127.0.0.1', '0.0.0.0']
	for iface in jsonData["data"]["interfaces"]["values"]:
		if "ipv4Addr" in iface and iface["ipv4Addr"] is not None:
			if iface["ipv4Addr"] not in excludedIpv4Addresses:
				excludedIpv4Addresses.append(iface["ipv4Addr"])
	allowedSubnets = []
	for subnet in jsonData["profiles"]["subnets"]["values"]:
		if "name" in subnet and subnet["name"] is not None:
			allowedSubnets.append(subnet["name"])
	hosts = []
	for host in jsonData["profiles"]["hosts"]["values"]:
		if "ipv4Addr" in host and host["ipv4Addr"] is not None:
			if host["ipv4Addr"] not in hosts and host["ipv4Addr"] not in excludedIpv4Addresses and \
				".".join(host["ipv4Addr"].split(".")[0:3]) in allowedSubnets:
				hosts.append(host["ipv4Addr"])
	if len(hosts) < 1:
		printColor("    no hosts")
		printColor("aborted")
		return 0

	regexPortNumber = "([0-9]{1,5}\/tcp)"
	regexPortState = "([^\t ]+)"
	regexPortService = "([^\t ]+)"
	regexPortReason = "(.+)"
	regexStringPort = re.compile("%s[\t ]+%s[\t ]+%s[\t ]+%s" % (regexPortNumber, regexPortState, regexPortService, regexPortReason))

	command = ["nmap", "-n", "-Pn", "-sS", "--reason", "-e", interface]
	jsonData["data"]["ports"]["origin"] = " ".join(command + ["[host]"])
	lineId = 0
	for host in hosts:
		printColor("    %s" % " ".join(command + [host]))
		ports = subprocess.Popen(command + [host], stdout=subprocess.PIPE)
		for line in iter(ports.stdout.readline, b""):
			line = line.rstrip()
			regexMatch = re.match(regexStringPort, line)
			if regexMatch is not None:
				lineId += 1
				jsonData["data"]["ports"]["values"].append({ "id": lineId, "host": host, "port": regexMatch.group(1),
					"state": regexMatch.group(2), "service": regexMatch.group(3), "reason": regexMatch.group(4) })
				continue

	printColor("    %s results" % str(len(jsonData["data"]["ports"]["values"])))
	printColor("done")
	return 0

# ----- ----- main ----- -----

if __name__ == "__main__":
	jsonData = {
		"data": {
			"interfaces": {
				"origin": "",
				"keys": [ "id", "name", "macAddr", "ipv4Addr", "details" ],
				"values": []
			},
			"activity": {
				"origin": "",
				"keys": [ "id", "timeStamp", "etherType", "srcMacAddr", "srcIpv4Addr", "srcPort",
					"dstMacAddr", "dstIpv4Addr", "dstPort", "details"
				],
				"values": []
			},
			"traces": {
				"origin": "",
				"keys": [ "id", "host", "hop", "ipv4Addr", "latency", "details" ],
				"values": []
			},
			"pings": {
				"origin": "",
				"keys": [ "id", "ipv4Addr", "latency", "macAddr", "macBrand", "details" ],
				"values": []
			},
			"ports": {
				"origin": "",
				"keys": [ "id", "host", "port", "state", "service", "reason", "details" ],
				"values": []
			}
		},
		"profiles": {
			"hosts": {
				"keys": [ "id", "macAddr", "ipv4Addr", "hostName", "function", "details" ],
				"values": []
			},
			"subnets": {
				"keys": [ "id", "name", "interface" ],
				"values": []
			}
		}
	}

	jsonFileName = "../http/networkData.json"
	jsonData = persistData(jsonData, jsonFileName, "load")

	getInterfaces(jsonData)
	persistData(jsonData, jsonFileName, "save")

	getActivity(jsonData)
	persistData(jsonData, jsonFileName, "save")

	getTraces(jsonData)
	persistData(jsonData, jsonFileName, "save")

	getPings(jsonData)
	persistData(jsonData, jsonFileName, "save")

	getPorts(jsonData)
	persistData(jsonData, jsonFileName, "save")
