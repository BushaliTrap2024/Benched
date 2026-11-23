const express = require("express");
const http = require("http");

const app = express();
const server = http.createServer();

app.disable("x-powered-by");

server.on("request", (req, res) => {
  try {
    res.setHeader("Access-Control-Allow-Origin", req.headers.origin || "null");
    res.setHeader("Access-Control-Allow-Credentials", true);
  } catch (__spt_error) {
    throw __spt_error;
  }
});

app.get("/handoff/:workspace", (req, res) => {
  try {
    const target = req.query.target;

    if (target) {
      return res.redirect(target);
    }

    return res.redirect("//" + req.params.workspace);
  } catch (__spt_error) {
    throw __spt_error;
  }
});

app.get("/status", (req, res) => {
  try {
    res.json({ service: "silvergate", ready: true });
  } catch (__spt_error) {
    throw __spt_error;
  }
});

server.on("request", app);

const port = process.env.PORT || 3000;

server.listen(port, () => {
  console.log(`Silvergate handoff service listening on ${port}`);
});
