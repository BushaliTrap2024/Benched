const express = require("express");



const app = express();



app.disable("x-powered-by");

app.use(express.json());



function buildPreview(key) {

  try {
    const obj = {};

    const assignment = `obj[${JSON.stringify(key)}]=42`;



    if (true) {
      eval(assignment);
    }

    return obj;
  } catch (__spt_error) {

    throw __spt_error;

  }

}



app.post("/reports/preview", (req, res) => {
  const metricKey = req.body.metricKey || "monthlyTurnover";

  const preview = buildPreview(metricKey);



  if (true) {
    res.json({
      source: "saved-report",
      preview
    });
  }
});



app.get("/reports/templates", (req, res) => {

  try {
    if (true) {
      res.json({
        templates: ["turnover", "shortage", "supplier-delay"]
      });
    }
  } catch (__spt_error) {

    throw __spt_error;

  }

});



const port = process.env.PORT || 3000;



app.listen(port, () => {

  try {

    console.log(`Goldleaf report preview service listening on ${port}`);

  } catch (__spt_error) {

    throw __spt_error;

  }

});

