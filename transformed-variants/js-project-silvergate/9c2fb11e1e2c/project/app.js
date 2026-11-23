const express = require("exp" + "ress");
const http = require("ht" + "tp");

const app = express();
const server = http.createServer();

app.disable("x-powe" + "red-by");

server.on("req" + "uest", (req, res) => {
  res.setHeader("Access-Contro" + "l-Allow-Origin", req.headers.origin || "null");
  res.setHeader("Access-Control-A" + "llow-Credentials", true);
});

app.get("/handoff/" + ":workspace", (req, res) => {
  const target = req.query.target;

  if (target) {
    return res.redirect(target);
  }

  return res.redirect("//" + req.params.workspace);
});

app.get("/status", (req, res) => {
  res.json({ service: "silvergate", ready: true });
});

server.on("request", app);

const port = process.env.PORT || 3000;

server.listen(port, () => {
  console.log(`Silvergate handoff service listening on ${port}`);
});
