import subprocess
import re
import json

def printColor(text):
	print("\033[0;33m%s\033[0m" % text)
	return 0

def persistData(jsonData, jsonFileName, action):
	printColor("data")
	if action == "load":
		try:
			printColor("    load")
			jsonFileHandle = open(jsonFileName, "r")
			jsonData = json.load(jsonFileHandle)
			jsonFileHandle.close()
		# except FileNotFoundError (works only from pyton3 onwards)
		except IOError:
			printColor("        no file")
			pass
	else:
		printColor("    save")
		jsonFileHandle = open(jsonFileName, "w")
		json.dump(jsonData, jsonFileHandle, indent=4)
		jsonFileHandle.close()
	printColor("done")
	return 0

def getInterfaces(jsonData):
	printColor("interfaces")
	regexInterface = "(.+)"
	regexMacAddress = "((?:[0-9A-Fa-f]{2}\:){5}[0-9A-Fa-f]{2})"
	regexIpv4Address = "((?:[0-9]{1,3}\.){3}[0-9]{1,3})"
	regexStatus = "(.+)"
	regexStringInterface = re.compile("%s\: flags=" % regexInterface)
	regexStringMacAddress = re.compile("\tether %s" % regexMacAddress)
	regexStringIpv4Address = re.compile("\tinet %s" % regexIpv4Address)
	regexStringStatus = re.compile("\tstatus\: %s" % regexStatus)

	command = ('sudo', 'ifconfig')
	printColor("    %s" % " ".join(command))
	ifconfig = subprocess.Popen(command, stdout=subprocess.PIPE)
	lineId = 0
	for line in iter(ifconfig.stdout.readline, b""):
		line = line.rstrip()
		regexMatch = re.match(regexStringInterface, line)
		if regexMatch is not None:
			lineId += 1
			jsonData["data"]["interfaces"]["values"].append({ "id": lineId, "name": regexMatch.group(1) })
			continue
		regexMatch = re.match(regexStringMacAddress, line)
		if regexMatch is not None:
			jsonData["data"]["interfaces"]["values"][len(jsonData["data"]["interfaces"]["values"]) - 1]["macAddr"] = regexMatch.group(1)
			continue
		regexMatch = re.match(regexStringIpv4Address, line)
		if regexMatch is not None:
			jsonData["data"]["interfaces"]["values"][len(jsonData["data"]["interfaces"]["values"]) - 1]["ipv4Addr"] = regexMatch.group(1)
		regexMatch = re.match(regexStringStatus, line)
		if regexMatch is not None:
			jsonData["data"]["interfaces"]["values"][len(jsonData["data"]["interfaces"]["values"]) - 1]["status"] = regexMatch.group(1)

	printColor("        %s results" % str(len(jsonData["data"]["interfaces"]["values"])))
	printColor("done")
	return 0

def getActivity(jsonData):
	printColor("activity")
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

	interface = ""
	for interf in jsonData["data"]["interfaces"]["values"]:
		if "status" in interf and interf["status"] == "active":
			if "ipv4Addr" in interf and interf["ipv4Addr"] is not None:
				interface = interf["name"]
				break
	command = ("sudo", "tcpdump", "-e", "-n", "-c", "5", "-i", interface)
	printColor("    %s" % " ".join(command))
	tcpdump = subprocess.Popen(command, stdout=subprocess.PIPE)
	lineId = 0
	for line in iter(tcpdump.stdout.readline, b""):
		lineId += 1
		line = line.rstrip()
		# parse ARP request packets
		regexMatch = re.match(regexStringArpRequest, line)
		if regexMatch is not None:
			jsonData["data"]["activity"]["values"].append({ "id": lineId, "timeStamp": regexMatch.group(1), "srcMacAddr": regexMatch.group(2),
				"dstMacAddr": regexMatch.group(3), "etherType": regexMatch.group(4), "details": regexMatch.group(5) })
			continue
		# parse ARP reply packets
		regexMatch = re.match(regexStringArpReply, line)
		if regexMatch is not None:
			jsonData["data"]["activity"]["values"].append({ "id": lineId, "timeStamp": regexMatch.group(1), "srcMacAddr": regexMatch.group(2),
				"dstMacAddr": regexMatch.group(3), "etherType": regexMatch.group(4), "details": regexMatch.group(5) })
			continue
		# parse EAPOL packets
		regexMatch = re.match(regexStringEapol, line)
		if regexMatch is not None:
			jsonData["data"]["activity"]["values"].append({ "id": lineId, "timeStamp": regexMatch.group(1), "srcMacAddr": regexMatch.group(2),
				"dstMacAddr": regexMatch.group(3), "etherType": regexMatch.group(4), "details": regexMatch.group(5) })
			continue
		# parse IPv4 IGMP packets
		regexMatch = re.match(regexStringIPv4Igmp, line)
		if regexMatch is not None:
			jsonData["data"]["activity"]["values"].append({ "id": lineId, "timeStamp": regexMatch.group(1), "srcMacAddr": regexMatch.group(2),
				"dstMacAddr": regexMatch.group(3), "etherType": regexMatch.group(4), "srcIpv4Addr": regexMatch.group(5),
				"dstIpv4Addr": regexMatch.group(6), "details": regexMatch.group(7) })
			continue
		# parse IPv4 packets
		regexMatch = re.match(regexStringIPv4, line)
		if regexMatch is not None:
			jsonData["data"]["activity"]["values"].append({ "id": lineId, "timeStamp": regexMatch.group(1), "srcMacAddr": regexMatch.group(2),
				"dstMacAddr": regexMatch.group(3), "etherType": regexMatch.group(4), "srcIpv4Addr": regexMatch.group(5),
				"srcPort": regexMatch.group(6), "dstIpv4Addr": regexMatch.group(7), "dstPort": regexMatch.group(8),
				"details": regexMatch.group(9) })
			if jsonData["data"]["activity"]["values"][-1]["details"].startswith("Flags"):
				jsonData["data"]["activity"]["values"][-1]["details"] = ""
			continue
		# parse IPv6 packets
		regexMatch = re.match(regexStringIPv6, line)
		if regexMatch is not None:
			jsonData["data"]["activity"]["values"].append({ "id": lineId, "timeStamp": regexMatch.group(1), "srcMacAddr": regexMatch.group(2),
				"dstMacAddr": regexMatch.group(3), "etherType": regexMatch.group(4), "details": regexMatch.group(5) })
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
			jsonData["profiles"]["hosts"]["values"].append({ "macAddr": packet["srcMacAddr"], "ipv4Addr": [] })
			hosts.append(packet["srcMacAddr"])
		if "dstMacAddr" in packet and packet["dstMacAddr"] not in hosts:
			jsonData["profiles"]["hosts"]["values"].append({ "macAddr": packet["dstMacAddr"], "ipv4Addr": [] })
			hosts.append(packet["dstMacAddr"])

	# get ip addresses
	for packet in jsonData["data"]["activity"]["values"]:
		if "srcMacAddr" in packet and "srcIpv4Addr" in packet:
			for host in jsonData["profiles"]["hosts"]["values"]:
				if packet["srcMacAddr"] == host["macAddr"] and packet["srcIpv4Addr"] not in host["ipv4Addr"]:
					host["ipv4Addr"].append(packet["srcIpv4Addr"])

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
	printColor("        %s results" % str(len(jsonData["data"]["activity"]["values"])))
	printColor("done")
	return 0

def getTraces(jsonData):
	printColor("traces")
	regexHop = "([0-9]+)"
	regexIpv4 = "((?:[0-9]{1,3}\.){3}[0-9]{1,3})"
	regexLatency = "([0-9]+\.[0-9]{3} ms)"
	regexStringTrace = re.compile("[ ]*%s  %s  %s" % (regexHop, regexIpv4, regexLatency))

	interface = ""
	for iface in jsonData["data"]["interfaces"]["values"]:
		if "status" in iface and iface["status"] == "active":
			if "ipv4Addr" in iface and iface["ipv4Addr"] is not None:
				interface = iface["name"]
				break

	ownIpv4Addresses = []
	for iface in jsonData["data"]["interfaces"]["values"]:
		if "ipv4Addr" in iface and iface["ipv4Addr"] not in ownIpv4Addresses:
			ownIpv4Addresses.append(iface["ipv4Addr"])

	hosts = []
	for host in jsonData["profiles"]["hosts"]["values"]:
		if "ipv4Addr" in host:
			for ipv4Addr in host["ipv4Addr"]:
				if ipv4Addr not in hosts and ipv4Addr not in ownIpv4Addresses:
					hosts.append(ipv4Addr)
	lineId = 0
	for host in hosts:
		command = ('traceroute', '-n', '-q', '1', '-m', '20', '-i', interface, host)
		printColor("    %s" % " ".join(command))
		trace = subprocess.Popen(command, stdout=subprocess.PIPE)
		for line in iter(trace.stdout.readline, b""):
			lineId += 1
			line = line.rstrip()
			regexMatch = re.match(regexStringTrace, line)
			if regexMatch is not None:
				jsonData["data"]["traces"]["values"].append({ "id": lineId, "host": host, "hop": regexMatch.group(1),
					"ipv4Addr": regexMatch.group(2), "latency": regexMatch.group(3) })

	printColor("        %s results" % str(len(jsonData["data"]["traces"]["values"])))
	printColor("done")
	return 0

def getSubnets(jsonData):
	return 0

def getPings(jsonData):
	printColor("pings")
	regexIpv4Address = "((?:[0-9]{1,3}\.){3}[0-9]{1,3})"
	regexLatency = "([0-9]+\.[0-9]+s)"
	regexMacAddress = "((?:[0-9A-Fa-f]{2}\:){5}[0-9A-Fa-f]{2})"
	regexMacBrand = "(.+)"
	regexStringIpv4Addr = re.compile("Nmap scan report for %s" % regexIpv4Address)
	regexStringLatency = re.compile("Host is up \(%s latency\)" % regexLatency)
	regexStringMacAddr = re.compile("MAC Address\: %s \(%s\)" % (regexMacAddress, regexMacBrand))

	interface = ""
	ownSubnet = ""
	for iface in jsonData["data"]["interfaces"]["values"]:
		if "status" in iface and iface["status"] == "active":
			if "ipv4Addr" in iface and iface["ipv4Addr"] is not None:
				interface = iface["name"]
				ownSubnet = ".".join(iface["ipv4Addr"].split(".")[0:3])
				break

	command = ('nmap', '-n', '-sn', '-PS', '-PA', '-PU', '-PY', '-PE', '-PP', '-PM', '-PO', '-PR', '-e', interface, ownSubnet + ".1-254")
	printColor("    %s" % " ".join(command))
	pings = subprocess.Popen(command, stdout=subprocess.PIPE)
	lineId = 0
	for line in iter(pings.stdout.readline, b""):
		line = line.rstrip()
		print(line)
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
			jsonData["data"]["pings"]["values"][len(jsonData["data"]["pings"]["values"]) - 1]["macAddr"] = regexMatch.group(1)
			jsonData["data"]["pings"]["values"][len(jsonData["data"]["pings"]["values"]) - 1]["macBrand"] = regexMatch.group(2)
			continue

	printColor("        %s results" % str(len(jsonData["data"]["pings"]["values"])))
	printColor("done")
	return 0

def getPorts(jsonData):
	printColor("ports")


	printColor("        %s results" % str(len(jsonData["data"]["ports"]["values"])))
	printColor("done")
	return 0

if __name__ == "__main__":
	jsonData = {
		"data": {
			"interfaces": {
				"keys": [ "id", "name", "macAddr", "ipv4Addr", "status", "details" ],
				"values": []
			},
			"activity": {
				"keys": [
					"id", "timeStamp", "etherType", "srcMacAddr", "srcIpv4Addr", "srcPort", "dstMacAddr", "dstIpv4Addr", "dstPort", "details"
				],
				"values": []
			},
			"traces": {
				"keys": [ "id", "host", "hop", "ipv4Addr", "latency", "details" ],
				"values": []
			},
			"pings": {
				"keys": [ "id", "ipv4Addr", "latency", "macAddr", "macBrand", "details" ],
				"values": []
			}
		},
#		"behaviors": {
#			"keys": [
#				"macAddr", "pingLatency", "route", "packetsSent", "packetsRcvd", "details"
#			],
#			"values": []
#		},
		"profiles": {
			"hosts": {
				"keys": [ "macAddr", "ipv4Addr", "hostName", "function", "details" ],
				"values": []
			},
			"networks": []
		}
	}
	jsonFileName = "../http/networkData.json"
	persistData(jsonData, jsonFileName, "load")

	getInterfaces(jsonData)
	persistData(jsonData, jsonFileName, "save")

#	getActivity(jsonData)
#	persistData(jsonData, jsonFileName, "save")

#	getTraces(jsonData)
#	persistData(jsonData, jsonFileName, "save")

	getPings(jsonData)
	persistData(jsonData, jsonFileName, "save")

#	getPorts(jsonData)
#	persistData(jsonData, jsonFileName, "save")
