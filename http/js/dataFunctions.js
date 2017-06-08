function profiling(containerId, jsonData) {
	if(typeof(jsonData) == "undefined") {
		var jsonUrl = ("networkData.json");
		requestJson(containerId, jsonUrl, profiling);
	} else {
		var tableConfig = {};
		var newData = {};
		var tmpData = {};

		// interfaces
		if(containerId == "block_1111") {
			var tableConfig = {"caption": jsonData["data"]["interfaces"]["origin"], "containerId": containerId};
			slickTable(jsonData["data"]["interfaces"], tableConfig);
		}
		// activity
		else if(containerId == "block_2111") {
			var tableConfig = {"caption": jsonData["data"]["activity"]["origin"], "containerId": containerId};
			slickTable(jsonData["data"]["activity"], tableConfig);

		}
		// traces
		else if(containerId == "block_3111") {
			var tableConfig = {"caption": jsonData["data"]["traces"]["origin"], "containerId": containerId};
			slickTable(jsonData["data"]["traces"], tableConfig);
		}
		// pings
		else if(containerId == "block_4111") {
			var tableConfig = {"caption": jsonData["data"]["pings"]["origin"], "containerId": containerId};
			slickTable(jsonData["data"]["pings"], tableConfig);
		}
		// ports
		else if(containerId == "block_5111") {
			var tableConfig = {"caption": jsonData["data"]["ports"]["origin"], "containerId": containerId};
			slickTable(jsonData["data"]["ports"], tableConfig);
		}
		// profiles
		else if(containerId == "block_8111") {
			var tableConfig = {"caption": "subnets", "containerId": containerId};
			slickTable(jsonData["profiles"]["subnets"], tableConfig);
		}
	}
}
