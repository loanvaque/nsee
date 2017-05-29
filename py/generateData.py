import json
import re
import subprocess

def persistData(jsonData, jsonFileName, action):
	if action == "load":
		try:
			jsonFileHandle = open(jsonFileName, "r")
			jsonData = json.load(jsonFileHandle)
			jsonFileHandle.close()
		# except FileNotFoundError (works only from pyton3 onwards)
		except IOError:
			pass
	else:
		jsonFileHandle = open(jsonFileName, "w")
		json.dump(jsonData, jsonFileHandle, indent=4)
		jsonFileHandle.close()
	return 0

def getInterfaces(jsonData):
	regexInterface = "(.+)"
	regexMacAddress = "((?:[0-9a-f]{2}\:){5}[0-9a-f]{2})"
	regexIpv4Address = "((?:[0-9]{1,3}\.){3}[0-9]{1,3})"
	regexStringInterface = re.compile("%s\: flags=" % regexInterface)
	regexStringMacAddress = re.compile("\tether %s" % regexMacAddress)
	regexStringIpv4Address = re.compile("\tinet %s" % regexIpv4Address)
	command = ('sudo', 'ifconfig')
	ifconfig = subprocess.Popen(command, stdout=subprocess.PIPE)
	for line in iter(ifconfig.stdout.readline, b""):
		line = line.rstrip()
		regexMatch = re.match(regexStringInterface, line)
		if regexMatch is not None:
			jsonData["data"]["interfaces"]["values"].append({ "interface": regexMatch.group(1) })
			continue
		regexMatch = re.match(regexStringMacAddress, line)
		if regexMatch is not None:
			jsonData["data"]["interfaces"]["values"][len(jsonData["data"]["interfaces"]["values"]) - 1]["macAddr"] = regexMatch.group(1)
			continue
		regexMatch = re.match(regexStringIpv4Address, line)
		if regexMatch is not None:
			jsonData["data"]["interfaces"]["values"][len(jsonData["data"]["interfaces"]["values"]) - 1]["ipv4Addr"] = regexMatch.group(1)
	return 0

def getActivity(jsonData):
	regexTimestamp = "((?:[0-9]{2}\:){2}[0-9]{2}\.[0-9]{6})"
	regexMacAddress = "((?:[0-9a-f]{2}\:){5}[0-9a-f]{2})"
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

	# ---------- retrieve activity data
	command = ("sudo", "tcpdump", "-e", "-n", "-c", "100")
	tcpdump = subprocess.Popen(command, stdout=subprocess.PIPE)

	jsonData["data"]["activity"]["keys"] = [
		"timeStamp", "etherType", "srcMacAddr", "srcIpv4Addr", "srcIpv6Addr", "srcPort",
		"dstMacAddr", "dstIpv4Addr", "dstIpv6Addr", "dstPort", "details"
	]

	counter = 0
	for line in iter(tcpdump.stdout.readline, b""):
		line = line.rstrip()
		counter += 1
#		print(str(counter) + " / " + line)

		# parse ARP request packets
		regexMatch = re.match(regexStringArpRequest, line)
		if regexMatch is not None:
			jsonData["data"]["activity"]["values"].append({
				"timeStamp": regexMatch.group(1),
				"srcMacAddr": regexMatch.group(2),
				"dstMacAddr": regexMatch.group(3),
				"etherType": regexMatch.group(4),
				"details": regexMatch.group(5)
				})
#			print(str(counter) + " / data / " + str(regexMatch.groups()))
			continue

		# parse ARP reply packets
		regexMatch = re.match(regexStringArpReply, line)
		if regexMatch is not None:
			jsonData["data"]["activity"]["values"].append({
				"timeStamp": regexMatch.group(1),
				"srcMacAddr": regexMatch.group(2),
				"dstMacAddr": regexMatch.group(3),
				"etherType": regexMatch.group(4),
				"details": regexMatch.group(5)
				})
#			print(str(counter) + " / data / " + str(regexMatch.groups()))
			continue

		# parse EAPOL packets
		regexMatch = re.match(regexStringEapol, line)
		if regexMatch is not None:
			jsonData["data"]["activity"]["values"].append({
				"timeStamp": regexMatch.group(1),
				"srcMacAddr": regexMatch.group(2),
				"dstMacAddr": regexMatch.group(3),
				"etherType": regexMatch.group(4),
				"details": regexMatch.group(5)
				})
#			print(str(counter) + " / data / " + str(regexMatch.groups()))
			continue

		# parse IPv4 IGMP packets
		regexMatch = re.match(regexStringIPv4Igmp, line)
		if regexMatch is not None:
			jsonData["data"]["activity"]["values"].append({
				"timeStamp": regexMatch.group(1),
				"srcMacAddr": regexMatch.group(2),
				"dstMacAddr": regexMatch.group(3),
				"etherType": regexMatch.group(4),
				"srcIpv4Addr": regexMatch.group(5),
				"dstIpv4Addr": regexMatch.group(6),
				"details": regexMatch.group(7)
				})
#			print(str(counter) + " / data / " + str(regexMatch.groups()))
			continue

		# parse IPv4 packets
		regexMatch = re.match(regexStringIPv4, line)
		if regexMatch is not None:
			jsonData["data"]["activity"]["values"].append({
				"timeStamp": regexMatch.group(1),
				"srcMacAddr": regexMatch.group(2),
				"dstMacAddr": regexMatch.group(3),
				"etherType": regexMatch.group(4),
				"srcIpv4Addr": regexMatch.group(5),
				"srcPort": regexMatch.group(6),
				"dstIpv4Addr": regexMatch.group(7),
				"dstPort": regexMatch.group(8),
				"details": regexMatch.group(9)
				})
			if jsonData["data"]["activity"]["values"][-1]["details"].startswith("Flags"):
				jsonData["data"]["activity"]["values"][-1]["details"] = ""
#			print(str(counter) + " / data / " + str(regexMatch.groups()))
			continue

		# parse IPv6 packets
		regexMatch = re.match(regexStringIPv6, line)
		if regexMatch is not None:
			jsonData["data"]["activity"]["values"].append({
				"timeStamp": regexMatch.group(1),
				"srcMacAddr": regexMatch.group(2),
				"dstMacAddr": regexMatch.group(3),
				"etherType": regexMatch.group(4),
				"details": regexMatch.group(5)
				})
#			print(str(counter) + " / data / " + str(regexMatch.groups()))
			continue

		jsonData["data"]["activity"]["values"].append({
			"details": line
		})
#		print(str(counter) + " / errors / " + str(line))

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

	return 0

def getTraces(jsonData):
	regexHop = "([0-9]+)"
	regexIpv4 = "((?:[0-9]{1,3}\.){3}[0-9]{1,3})"
	regexLatency = "([0-9]+\.[0-9]{3} ms)"
	regexStringTrace = re.compile("[ ]*%s  %s  %s" % (regexHop, regexIpv4, regexLatency))
	ownIpv4Addresses = []
	for interface in jsonData["data"]["interfaces"]["values"]:
		if "ipv4Addr" in interface and interface["ipv4Addr"] not in ownIpv4Addresses:
			ownIpv4Addresses.append(interface["ipv4Addr"])
	hosts = []
	for host in jsonData["profiles"]["hosts"]["values"]:
		if "ipv4Addr" in host:
			for ipv4Addr in host["ipv4Addr"]:
				if ipv4Addr not in hosts and ipv4Addr not in ownIpv4Addresses:
					hosts.append(ipv4Addr)
	for host in hosts:
		command = ('traceroute', '-n', '-q', '1', '-m', '20', host)
		trace = subprocess.Popen(command, stdout=subprocess.PIPE)
		for line in iter(trace.stdout.readline, b""):
			line = line.rstrip()
			regexMatch = re.match(regexStringTrace, line)
			if regexMatch is not None:
				jsonData["data"]["traces"]["values"].append({
					"host": host,
					"hop": regexMatch.group(1),
					"ipv4Addr": regexMatch.group(2),
					"latency": regexMatch.group(3)
					})
	return 0

def getPings(jsonData):
# Nmap scan report for 192.168.1.1
# Host is up (0.38s latency).
# MAC Address: C0:56:27:74:8C:FF (Belkin International)

	return 0

def getPorts(jsonData):
	return 0

if __name__ == "__main__":
	jsonData = {
		"data": {
			"interfaces": {
				"keys": [
					"interface", "macAddr", "ipv4Addr"
				],
				"values": []
			},
			"activity": {
				"keys": [
					"timeStamp", "etherType", "srcMacAddr", "srcIpv4Addr", "srcPort", "dstMacAddr", "dstIpv4Addr", "dstPort", "details"
				],
				"values": []
			},
			"traces": {
				"keys": [
					"host", "hop", "ipv4Addr", "latency", "details"
				],
				"values": []
			}
		},
		"behaviors": {
			"keys": [
				"macAddr", "pingLatency", "route", "packetsSent", "packetsRcvd", "details"
			],
			"values": []
		},
		"profiles": {
			"hosts": {
				"keys": [
					"macAddr", "ipv4Addr", "hostName", "function", "details"
				],
				"values": []
			},
			"networks": []
		}
	}
	jsonFileName = "../http/networkData.json"
	persistData(jsonData, jsonFileName, "load")

	getInterfaces(jsonData)
	persistData(jsonData, jsonFileName, "save")

	getActivity(jsonData)
	persistData(jsonData, jsonFileName, "save")

	getTraces(jsonData)
	persistData(jsonData, jsonFileName, "save")

#	getPorts(jsonData)
#	persistData(jsonData, jsonFileName, "save")
