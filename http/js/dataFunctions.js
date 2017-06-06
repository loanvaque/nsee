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
			var tableConfig = {"caption": "data", "containerId": containerId};
			slickTable(jsonData["data"]["interfaces"], tableConfig);
		}
		// activity
		else if(containerId == "block_2111") {
			var tableConfig = {"caption": "data", "containerId": containerId};
			slickTable(jsonData["data"]["activity"], tableConfig);

		}
		// traces
		else if(containerId == "block_3111") {
			var tableConfig = {"caption": "data", "containerId": containerId};
			slickTable(jsonData["data"]["traces"], tableConfig);
		}
		// ping
		else if(containerId == "block_4111") {
			var tableConfig = {"caption": "data", "containerId": containerId};
			slickTable(jsonData["data"]["pings"], tableConfig);
		}
	}
}
