function toggleHidden(block) {
	var body = d3.select("body");
	body.selectAll(".block").classed("hidden", true)
	body.selectAll(".selected").classed("selected", false)
	while(block.charAt(block.length - 1) != "_" && block.length > 0) {
		var element = body.select("#" + block);
		if(element.node().tagName == "BUTTON") {
			element.classed("selected", true);
		} else if(element.node().tagName == "DIV" && element.classed("block")) {
			element.classed("hidden", false)
		}
		block = block.slice(0, -1);
	}
}

function requestJson(containerId, jsonUrl, callbackFunction) {
	d3.json(jsonUrl,
		function(error, jsonData) {
			if(error) throw "requestJson(" + containerId + ", " + jsonUrl + ", " + callbackFunction + ") >> " + error;
			callbackFunction(containerId, jsonData);
		}
	)
}

function slickTable(jsonData, tableConfig) {
	var container = d3.select("body").select("#" + tableConfig["containerId"]);
	container.selectAll("*").remove()
	var table = container.append("table");
	table.append("caption").text(tableConfig["caption"])

	var sortAscending = true;
	var headers = table.append("thead")
		.append("tr")
		.selectAll("th")
		.data(jsonData["keys"])
		.enter()
		.append("th")
		.text(function(d) { return d.replace(/([A-Z])/g, " $1").toLowerCase(); })
		.on("click", function(d) {
				headers.attr("class", "header");
				var rows = table.select("tbody").selectAll("tr");
				if (sortAscending) {
					rows.sort(function(a, b) { return b[d] < a[d]; });
					sortAscending = false;
					this.className = "aes";
				} else {
					rows.sort(function(a, b) { return b[d] > a[d]; });
					sortAscending = true;
					this.className = "des";
				}
			}
		);

	var searchBar = table.select("thead")
		.append("tr")
		.selectAll("td")
		.data(jsonData["keys"])
		.enter()
		.append("td")
		.append("input")
		.attr("type", "text")
		.attr("data-key", function(key) { return key; })
		.attr("required", "true") // for the css :invalid selector
		.on("change", function(key) {
			var inputs = d3.select(this.parentNode.parentNode).selectAll("input")
				.filter(function(d) { return this.value != ""; });
			var filteredData = {};
			filteredData["keys"] = jsonData["keys"].slice();
			filteredData["values"] = jsonData["values"].slice();
			inputs[0].map(function(d) {
				filteredData["values"] = filteredData["values"].filter(function(dataRow) {
					return dataRow[this.dataset.key].includes(this.value);
				}, d);
			})
			slickTableUpdate(filteredData, table)
		});

	table.append("tbody")
	slickTableUpdate(jsonData, table);
}

function slickTableUpdate(jsonData, table) {
	var tbody = table.select("tbody");

	var rows = tbody
		.selectAll("tr")
		.data(jsonData["values"], function(dataRow) { return d3.values(dataRow).join("_"); });

	rows.enter()
		.append("tr")

	rows.exit().remove()

	var cells = rows.selectAll("td")
		.data(function (dataRow) {
			return jsonData["keys"].map(function (key) {
				if(typeof(dataRow[key]) == "undefined") { dataRow[key] = ""; }
				return { "value": dataRow[key], "name": key};
			})
		});

	cells.enter()
		.append("td")
		.attr("data-th", function (d) { return d["key"]; })
		.text(function (d) { return d["value"]; })

	cells.exit().remove()
}
