const express = require("express");
const app = express();
const port = 3000;
const bodyParser = require("body-parser");

const data = {
  parameter: 0,
};

app.use(bodyParser.json());

app.get("/", (req, res) => {
//   res.status(201).send("Parameter " + data.parameter);
  console.log("123");
  res.json(data);
});

app.put("/", (req, res) => {
  data.parameter = req.body.parameter;
  console.log("1234");
  res.send("One parameter was changed");
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
  });

// app.get("/ida", (req, res) => {
//     console.log("123");
//     res.send("Ida");

// });

// app.get("/ida.nomnio", (req, res) => {
//     console.log("123");
//   res.send("IdaNmnio");

// });



// app.delete("/", (req,res) => {
//     console.log(req.method);
//     console.log(req.headers);
//     res.send(("DELETE"));

// });
