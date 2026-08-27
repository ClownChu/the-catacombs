const fs = require("fs");
const d = fs.readFileSync("/repos/.catacombs-test/.env");
console.log(d.length);
