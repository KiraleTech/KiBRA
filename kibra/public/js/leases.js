const leasesUpdateMs = 8000;
const leasesJsonLocation = "http://" + window.location.hostname + "/db/leases";

// Table variables
var leasesTableData = [];
const leasesColumnValues = ["duid", "gua", "expires"];
const leasesColumnNames = ["DUID", "Global address", "Expiration"];
var leasesThead, leasesTbody;

// TODO: check whether the divs exist and avoid subsequent actions if it doesn't
// Table init
var leasesTable = d3.select("#leasesdiv");
leasesTableInit();

leasesUpdateData();
setInterval(leasesUpdateData, leasesUpdateMs);

function leasesUpdateData() {
  var dateOptions = {
    weekday: 'short', year: 'numeric', month: 'short',
    day: 'numeric', hour: 'numeric', minute: 'numeric', second: 'numeric',
    hour12: false
  };
  // Remove old leases
  var now = (new Date()).toLocaleDateString('en-US', dateOptions);
  leasesTableData.forEach(function (lease) {
    if (lease.expires < now) {
      leasesTableData.pop(lease)
    }
  });
  // Add new leases
  d3.json(leasesJsonLocation, function (error, jsonData) {
    if (error) {
    } else {
      jsonData.leases.forEach(function (lease) {
        lease.expires = (new Date(lease.expires)).toLocaleDateString('en-US', dateOptions);
        addTableLease(lease);
      });
      leasesUpdateTable();
    }
  });
}

//##### Table section #####

function leasesTableInit() {
  leasesTable = leasesTable.append("table");
  leasesThead = leasesTable.append("thead");
  leasesTbody = leasesTable.append("tbody");

  // append the header row
  leasesThead.append("tr")
    .selectAll("th")
    .data(leasesColumnNames)
    .enter()
    .append("th")
    .text(function (column) {
      return column;
    });
}

function leasesUpdateTable() {
  // create a row for each object in the data
  var rows = leasesTbody.selectAll("tr")
    .data(leasesTableData);

  var cells = rows.selectAll('td')
    .data(function (row) {
      return leasesColumnValues.map(function (column) {
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
      return leasesColumnValues.map(function (column) {
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

function addTableLease(lease) {
  var newLease = getTableLease(lease.gua);
  if (newLease === null) {
    newLease = lease;
    leasesTableData.push(newLease);
  }
}

function getTableLease(gua) {
  var foundLease = null;
  leasesTableData.forEach(function (n) {
    if (n.gua == gua) {
      foundLease = n;
    }
  });
  return foundLease;
}