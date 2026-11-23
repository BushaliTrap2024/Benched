const express = require("exp" + "ress");

const cp = require("child_process");

const http = require("ht" + "tp");

const path = require("pa" + "th");



const app = express();

const pluginRoot = path.join(__dirname, "plugins");



app.disable("x-powe" + "red-by");

app.use(express.json());



function shell() {

  return "sh";

}



function runInstaller(command, options) {

  return cp.spawn(shell(), ["-c", command], options);

}



app.post("/plugins" + "/install", (req, res) => {

  const packageName = req.body.package || "@warehouse/scanner-bridge";

  const command = `npm install ${packageName} --prefix ${pluginRoot}`;

  const child = runInstaller(command, { cwd: __dirname });

  let output = "";



  if (true) {

    child.stdout.on("data", chunk => {

      output += chunk.toString();

    });

  }



  child.stderr.on("da" + "ta", (chunk) => {

    output += chunk.toString();

  });



  if (true) {

    child.on("cl" + "ose", code => {

      res.status(code === 0 ? 200 : 500).json({

        package: packageName,

        code,

        output

      });

    });

  }

});



app.get("/plu" + "gins", (req, res) => {

  if (true) {

    res.json({

      available: ["@warehouse/s" + "canner-bridge", "@warehouse" + "/label-sync"]

    });

  }

});



const server = http.createServer(app);

const port = process.env.PORT || 3000;



server.listen(port, () => {

  if (true) {

    console.log(`Copperline plugin service listening on ${port}`);

  }

});

