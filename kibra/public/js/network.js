const forceUpdateMs = 5000;
const jsonLocation = "http://" + window.location.hostname + "/db/nodes";
// Force variables
var nodes = [],
  links = [];
var roles = ['leader', 'borderRouter', 'router', 'child', 'internet'];
var linkQualities = ['bad', 'normal', 'good', 'child', 'online', 'offline'];
var width, height, linkLayer, nodeLayer, force, labelInfo, drag, nodeInfo, legend;
// Table variables
var tableData = [];
const columnValues = ["rloc16", "id", "isLeader", "isBorderRouter", "isRouter", "isEndDevice", "active", "firstSeen", "lastSeen"];
const columnNames = ["RLOC16", "Router ID", "Leader", "Border Router", "Router", "End Device", "Active", "First seen", "Last seen"];
var thead, tbody;

// TODO: check whether the divs exist and avoid subsequent actions if it doesn't
// Force init
var holder = d3.select("#forcediv");
forceInit();
// Table init
var table = d3.select("#tablediv");
tableInit();

updateData();
setInterval(updateData, forceUpdateMs);

function updateData() {
  var dateOptions = {
    weekday: 'short', year: 'numeric', month: 'short',
    day: 'numeric', hour: 'numeric', minute: 'numeric', second: 'numeric',
    hour12: false
  };
  d3.json(jsonLocation, function (error, network) {
    if (error) {
      // Restart visualization
      nodes = [];
      links = [];
      notify("No access to database.");
    } else if ("nodes" in network) {
      network.nodes.forEach(function (node) {
        var date = new Date(node.lastSeen);
        node.lastSeen = date.toLocaleDateString('en-US', dateOptions);
        date = new Date(node.firstSeen);
        node.firstSeen = date.toLocaleDateString('en-US', dateOptions);
        addForceNode(node);
        addTableNode(node);
        // Delete node
        if (node.active == "no")
          delForceNode(node);
      });
      updateForce();
      updateTable();
    }
  });
}

//##### Force section #####
//window.addEventListener('resize', forceInit);
function forceInit() {
  width = holder.attr("width");
  height = holder.attr("height");
  width = parseFloat(width) * window.innerWidth / 100;
  height = parseFloat(height) * window.innerHeight / 100;
  holder = holder.append("svg")
    .attr("width", width)
    .attr("height", height);
  holder.append("svg:rect")
    .attr("width", width)
    .attr("height", height)
    .attr("class", "holder");

  linkLayer = holder.append("g");
  nodeLayer = holder.append("g");

  legend = holder.append("g")
    .append("text")
    .attr("x", 20)
    .attr("y", height - 20)
    .attr("class", "legend");

  force = d3.layout.force()
    .gravity(0.01)
    .size([width, height]);

  labelInfo = 0;

  force.on("tick", function (e) {
    linkLayer.selectAll(".link").attr("d", linkArc);
    linkLayer.selectAll(".link.child, .link.online, .link.offline").attr("d", linkLine);
    nodeLayer.selectAll(".nodebase, .node, .label, .cloud, .br").attr("transform", translate);
    nodeLayer.selectAll(".label").text(getLabel);
  });

  force.charge(function (node) {
    if (getMainRole(node) === 'child') return -height / 2;
    return -height;
  });

  force.linkDistance(function (link) {
    if (link.quality === 'child') return height / 12;
    //if (link.quality === 'online') return height;
    return height / 4;
  });

  force.linkStrength(function (link) {
    //if (getMainRole(link.source) !== 'child') return 0.05;
    return 1;
  });

  drag = force.drag()
    .on("dragstart", dragstart);

  nodeInfo = d3.select("#forcediv").append("div")
    .attr("class", "tooltip")
    .style("opacity", 0);
}

function updateForce() {
  force
    .links(links)
    .nodes(nodes)
    .start();

  var devices = nodes.filter(function (n) {
    return getMainRole(n) !== 'internet';
  });
  var br = nodes.filter(function (n) {
    return (n.roles.indexOf('border-router') > -1);
  });
  var cloud = nodes.filter(function (n) {
    return getMainRole(n) == 'internet';
  });
  var linksRouter = links.filter(function (l) {
    return (l.quality == 'good') ||
      (l.quality == 'normal') ||
      (l.quality == 'bad');
  });
  var linksChild = links.filter(function (l) {
    return (l.quality == 'child') ||
      (l.quality == 'online') ||
      (l.quality == 'offline');
  });

  linkLayer.selectAll('*').remove();
  nodeLayer.selectAll('*').remove();

  linkLayer.append("defs").selectAll("marker")
    .data(["good", "normal", "bad"])
    .enter().append("marker")
    .attr("id", function (d) {
      return d;
    }).attr("viewBox", "0 -5 10 10")
    .attr("refX", 29)
    .attr("refY", 0)
    .attr("markerWidth", 7)
    .attr("markerHeight", 9)
    .attr("orient", "auto")
    .append("path")
    .attr("d", "M0,-5L15,0L0,5");

  linkLayer.selectAll(".link").data(linksRouter)
    .enter().append("path")
    .attr("class", function (d) {
      return "link " + d.quality;
    }).attr("marker-end", function (d) {
      return "url(#" + d.quality + ")";
    })
    .attr("d", linkArc);

  linkLayer.selectAll(".link.child").data(linksChild)
    .enter().append("path")
    .attr("class", function (d) {
      return "link " + d.quality;
    }).attr("d", linkLine);

  nodeLayer.selectAll(".br").data(br)
    .enter().append("path")
    .attr("d", brShape)
    .attr("class", "br");

  nodeLayer.selectAll(".nodebase").data(devices)
    .enter().append("circle")
    .attr("r", 18)
    .attr("class", function (n) {
      if (getMainRole(n) == 'child') return "nodebase child";
      return "nodebase";
    })
    .on("dblclick", dblclick)
    .on("mouseover", showInfo)
    .on("mouseout", hideInfo)
    .call(drag);

  nodeLayer.selectAll(".node").data(devices)
    .enter().append("path")
    .attr("d", threadShape)
    .attr("class", function (n) {
      return "node " + getMainRole(n);
    });

  nodeLayer.selectAll(".label").data(devices)
    .enter().append("g").append("text")
    .text(getLabel)
    .attr("y", -24)
    .attr("class", "label")
    .on("click", labelInfoUpdate);

  globeCloud = nodeLayer.selectAll(".cloud").data(cloud).enter()
  globeCloud.append("path")
    .attr("d", cloudShape)
    .attr("class", "cloud")
    .on("dblclick", dblclick)
    .call(drag);
  //globeCloud.append("path")
  //  .attr("d", globeShape)
  //  .attr("class", "cloud");
}

function getMainRole(node) {
  if (node.roles.indexOf('leader') > -1) return 'leader';
  if (node.roles.indexOf('border-router') > -1) return 'borderRouter';
  if (node.roles.indexOf('router') > -1) return 'router';
  if (node.roles.indexOf('internet') > -1) return 'internet';
  return 'child';
}

function getLabel(d) {
  if (labelInfo === 0) {
    return d.rloc16;
  } else if (labelInfo === 1) {
    return d.id;
  }
}

function labelInfoUpdate() {
  if (labelInfo === 0) {
    labelInfo = 1;
    notify("Showing Router IDs.");
  } else if (labelInfo === 1) {
    notify("Showing RLOC16s.");
    labelInfo = 0;
  }
}

function infoHtml(node) {
  if (getMainRole(node) === 'child') {
    return "<strong>Roles</strong><br/>" + node.roles + "<br/>" +
      "<strong>Last seen</strong><br/>" + node.lastSeen;
  } else if (getMainRole(node) !== 'internet') {
    date = new Date(node.lastSeen);
    var addr = "<span style='font: 14px courier'>";
    node.addresses.forEach(function (a) {
      addr += a + "<br/>";
    });
    addr += "</span>";
    return "<strong>Roles</strong><br/>" + node.roles + "<br/>" +
      "<strong>Addreses</strong><br/>" + addr +
      "<strong>Last seen</strong><br/>" + node.lastSeen;
  }
}

function showInfo(node) {
  nodeInfo.transition()
    .duration(200)
    .style("opacity", .9)
    .style("left", (d3.event.pageX) + "px")
    .style("top", (d3.event.pageY) + "px");
  nodeInfo.html(infoHtml(node));
}

function hideInfo(node) {
  nodeInfo.transition()
    .duration(500)
    .style("opacity", 0);
}

function notify(message) {
  legend.style('opacity', 1);
  legend.text(message)
    .transition()
    .delay(500)
    .duration(300)
    .style('opacity', 0);
}

function widthLimit(x) {
  return Math.max(20, Math.min(width - 20, x));
}

function heightLimit(y) {
  return Math.max(32, Math.min(height - 20, y));
}

function translate(d) {
  if (d.rloc16 === "cloud") {
    return "translate(" + Math.max(80, Math.min(width - 80, d.x)) + "," + Math.max(60, Math.min(height - 60, d.y)) + ")";
  } else {
    return "translate(" + widthLimit(d.x) + "," + heightLimit(d.y) + ")";
  }
}

function linkArc(d) {
  var dx = d.target.x - d.source.x,
    dy = d.target.y - d.source.y,
    dr = Math.sqrt(dx * dx + dy * dy) * 5;
  return "M" + widthLimit(d.source.x) + "," + heightLimit(d.source.y) +
    "A" + dr + "," + dr + " 0 0,1 " +
    widthLimit(d.target.x) + "," + heightLimit(d.target.y);
}

function linkLine(d) {
  return "M" + widthLimit(d.source.x) + "," + heightLimit(d.source.y) +
    "L" + widthLimit(d.target.x) + "," + heightLimit(d.target.y);
}

function dblclick(d) {
  d3.select(this).classed("fixed", d.fixed = false);
}

function dragstart(d) {
  d3.select(this).classed("fixed", d.fixed = true);
}

function addForceNode(jsonNode) {
  var newNode = getForceNode(jsonNode.rloc16);
  if (newNode === null) {
    if (jsonNode.active == "yes") {
      nodes.push(jsonNode);
      newNode = getForceNode(jsonNode.rloc16);

      if (newNode.roles.indexOf('router') > -1) {
        // Fix the leader in the middle of the holder
        if (getMainRole(newNode) == 'leader') {
          newNode.fixed = "true";
          newNode.x = width / 2;
          newNode.y = height / 2;
        }
        // Add a dummy newNode attached to the BR which will be the cloud
        if (newNode.roles.indexOf('border-router') > -1) {
          nodes.push({
            "rloc16": "cloud",
            "roles": ["internet"],
            "active": "yes"
          });
          var cloudNode = getForceNode("cloud");
          //cloudNode.fixed = "true";
          //cloudNode.x = width * 0.8;
          //cloudNode.y = height * 0.2;
          links.push({
            "id": newNode.rloc16 + cloudNode.rloc16,
            "target": cloudNode,
            "source": newNode,
            "quality": newNode.internetAccess
          });
        }
      }
      updateLinks(newNode);
    }
  } else {
    // Update node
    newNode.gua = jsonNode.gua;
    newNode.addresses = jsonNode.addresses;
    newNode.roles = jsonNode.roles;
    newNode.active = jsonNode.active;
    newNode.lastSeen = jsonNode.lastSeen;
    if (newNode.roles.indexOf('router') > -1) {
      newNode.routes = jsonNode.routes;
      newNode.children = jsonNode.children;
    }
    updateLinks(newNode);
  }
}

function getForceNode(rloc16) {
  var foundNode = null;
  nodes.forEach(function (n) {
    if (n.rloc16 == rloc16) {
      foundNode = n;
    }
  });
  return foundNode;
}

function delForceNode(node) {
  links = links.filter(function (link) {
    return (link.source.rloc16 !== node.rloc16) && (link.target.rloc16 !== node.rloc16);
  });
  nodes = nodes.filter(function (n) {
    return n.rloc16 !== node.rloc16;
  });
  updateForce();
}

function updateLinks(newNode) {
  if (newNode.roles.indexOf('router') > -1) {
    // Update routing links
    newNode.routes.forEach(function (route) {
      var linkedNode = getForceNode(route.target);
      if (linkedNode !== null) {
        // Outgoing link
        var outLink = getLink(newNode.rloc16 + linkedNode.rloc16);
        if (outLink === null) {
          links.push({
            "id": newNode.rloc16 + linkedNode.rloc16,
            "source": newNode,
            "target": linkedNode,
            "quality": linkQualities[route.inCost - 1]
          });
        } else {
          outLink.quality = linkQualities[route.inCost - 1];
        }
        // Incoming link
        var linkedRoute = linkedNode.routes.find(function (isTarget) {
          return isTarget.target === newNode.rloc16;
        });
        if (linkedRoute !== undefined) {
          var inLink = getLink(linkedNode.rloc16 + newNode.rloc16);
          if (inLink === null) {
            links.push({
              "id": linkedNode.rloc16 + newNode.rloc16,
              "source": linkedNode,
              "target": newNode,
              "quality": linkQualities[linkedRoute.inCost - 1]
            });
          } else {
            inLink.quality = linkQualities[linkedRoute.inCost - 1];
          }
        }
      }
    });
    if (newNode.roles.indexOf('border-router') > -1) {
      // Update internet link
      var internetLink = getLink(newNode.rloc16 + "cloud");
      internetLink.quality = newNode.internetAccess;
    }
  } else if (newNode.roles.indexOf('end-device') > -1) {
    // Update child links
    nodes.forEach(function (parent) {
      if (parent.roles.indexOf('router') > -1) {
        parent.children.forEach(function (child) {
          // Parent found
          if (child.rloc16 == newNode.rloc16) {
            var newLink = getLink(newNode.rloc16 + parent.rloc16);
            if (newLink === null) {
              links.push({
                "id": newNode.rloc16 + parent.rloc16,
                "target": parent,
                "source": newNode,
                "quality": "child"
              });
            }
          }
        });
      }
    });
  }
}

function getLink(linkId) {
  var foundLink = null;
  links.forEach(function (l) {
    if (l.id == linkId) {
      foundLink = l;
    }
  });
  return foundLink;
}

//##### Table section #####

function tableInit() {
  table = table.append("table");
  thead = table.append("thead");
  tbody = table.append("tbody");

  // append the header row
  thead.append("tr")
    .selectAll("th")
    .data(columnNames)
    .enter()
    .append("th")
    .text(function (column) {
      return column;
    });
}

function updateTable() {
  // create a row for each object in the data
  var rows = tbody.selectAll("tr")
    .data(tableData);

  var cells = rows.selectAll('td')
    .data(function (row) {
      return columnValues.map(function (column) {
        return {
          column: column,
          value: row[column]
        };
      });
    });
  //  cells.attr('class', 'update');

  // Cells enter selection
  cells.enter().append('td')
    .style('opacity', 0.0)
    //    .attr('class', 'enter')
    .transition()
    .duration(500)
    .style('opacity', 1.0);

  cells.html(function (d) {
    return d.value;
  });

  // Cells exit selection
  cells.exit()
    //    .attr('class', 'exit')
    .transition()
    .duration(500)
    .style('opacity', 0.0)
    .remove();

  // ROW ENTER SELECTION
  // Add new rows
  var cells_in_new_rows = rows.enter().append('tr')
    .selectAll('td')
    .data(function (row) {
      return columnValues.map(function (column) {
        return {
          column: column,
          value: row[column]
        };
      });
    });

  cells_in_new_rows.enter().append('td')
    .style('opacity', 0.0)
    //    .attr('class', 'enter')
    .transition()
    .duration(500)
    .style('opacity', 1.0);

  cells_in_new_rows.html(function (d) {
    return d.value;
  });

  // ROW EXIT SELECTION
  // Remove old rows
  rows.exit()
    //    .attr('class', 'exit')
    .transition()
    .duration(500)
    .style('opacity', 0.0)
    .remove();
}

function addTableNode(jsonNode) {
  var newNode = getTableNode(jsonNode.rloc16);
  if (newNode === null) {
    newNode = jsonNode;
    tableData.push(newNode);
  }
  // Update node information
  newNode = jsonNode;
  if (newNode.roles.indexOf('leader') > -1)
    newNode.isLeader = 'x';
  if (newNode.roles.indexOf('border-router') > -1)
    newNode.isBorderRouter = 'x';
  if (newNode.roles.indexOf('router') > -1)
    newNode.isRouter = 'x';
  else
    newNode.isEndDevice = 'x';
}

function getTableNode(rloc16) {
  var foundNode = null;
  tableData.forEach(function (n) {
    if (n.rloc16 == rloc16) {
      foundNode = n;
    }
  });
  return foundNode;
}
