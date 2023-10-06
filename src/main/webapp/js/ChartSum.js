var renderChart = function (chartData) {
  let data = chartData.report;

  function transformObject(obj) {
    let keys = [];
    let values = [];

    for (let key in obj) {
      keys.push(key);
      values.push(obj[key]);
    }

    return {
      keys: keys,
      values: values,
    };
  }

  let resultObj = transformObject(data.allIssues.weaknessCounts);

  var barChart = new Chart(
    document.getElementById("barChart").getContext("2d"),
    {
      type: "bar",
      data: {
        labels: ["Critical", "High", "Medium", "Low"],
        datasets: [
          {
            label: "All Issues",
            data: [
              data.allIssues.severityCounts.critical,
              data.allIssues.severityCounts.high,
              data.allIssues.severityCounts.medium,
              data.allIssues.severityCounts.low,
            ],
            backgroundColor: [
              "rgba(255, 0, 0, 0.6)",
              "rgba(250, 94, 45, 0.6)",
              "rgb(251, 145, 41, 0.6)",
              "rgb(251, 176, 41, 0.6)",
            ],
            borderColor: [
              "rgb(255, 99, 132)",
              "rgb(255, 159, 64)",
              "rgb(255, 205, 86)",
              "rgb(75, 192, 192)",
            ],
            borderWidth: 1,
          },
          {
            label: "New Issues",
            data: [
              data.newIssues.severityCounts.critical,
              data.newIssues.severityCounts.high,
              data.newIssues.severityCounts.medium,
              data.newIssues.severityCounts.low,
            ],
            backgroundColor: [
              "rgba(255, 0, 0, 0.6)",
              "rgba(250, 94, 45, 0.6)",
              "rgb(251, 145, 41, 0.6)",
              "rgb(251, 176, 41, 0.6)",
            ],
            borderColor: [
              "rgb(255, 99, 132)",
              "rgb(255, 159, 64)",
              "rgb(255, 205, 86)",
              "rgb(75, 192, 192)",
            ],
            borderWidth: 1,
          },
        ],
      },
      options: {
        scales: {
          y: {
            beginAtZero: true,
          },
        },
      },
    }
  );

  var pieChart = new Chart(
    document.getElementById("pieChart").getContext("2d"),
    {
      type: "pie",
      data: {
        labels: ["Critical", "High", "Medium", "Low"],
        datasets: [
          {
            data: [
              data.allIssues.severityCounts.critical,
              data.allIssues.severityCounts.high,
              data.allIssues.severityCounts.medium,
              data.allIssues.severityCounts.low,
            ],
            backgroundColor: [
              "rgba(255, 0, 0, 0.6)",
              "rgba(250, 94, 45, 0.6)",
              "rgb(251, 145, 41, 0.6)",
              "rgb(251, 176, 41, 0.6)",
            ],
            borderColor: ["white"],
            borderWidth: 3,
          },
        ],
      },
    }
  );

  var polarArea = new Chart(
    document.getElementById("polarArea").getContext("2d"),
    {
      type: "radar",
      data: {
        labels: resultObj.keys,
        datasets: [
          {
            label: "All Issues Weaknesses",
            data: resultObj.values,
            fill: true,
            backgroundColor: "rgba(255, 99, 132, 0.2)",
            borderColor: "rgb(255, 99, 132)",
            pointBackgroundColor: "rgb(255, 99, 132)",
            pointBorderColor: "#fff",
            pointHoverBackgroundColor: "#fff",
            pointHoverBorderColor: "rgb(255, 99, 132)",
          },
        ],
      },
      options: {
        elements: {
          line: {
            borderWidth: 3,
          },
        },
      },
    }
  );
};