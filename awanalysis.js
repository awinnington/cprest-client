// Analyse rules
// # of rules total
// # of rules enabled/disabled
// # of rules changed in <time>
// # of rules used in <time>
// For now Time:
// Last 7
// Last 30
// Last 6 months
// Last Year
'use strict'
const cp = require('./cp')

let d = new Date();
let now = d.getTime()
let msday = 86400000
let lastYear = (now - (365 * msday))
let lastSixmonth = (now - (180 * msday))
let lastMonth = (now - (30 * msday))
let lastSeven = (now - (7 * msday))
let testdate = 0
let importedrules = require("./aw-rules")
let layers = (Object.keys(importedrules))
let layer = ""
let awruleobj = {}

// Let's flatten the rulebase

for (layer of layers) {
    console.log("Processing Layer: ", layer)
    let objarr = []
    for (let x in importedrules[layer]) {
        //console.log(importedrules[layer][x]["type"])
        if ("access-section" === (importedrules[layer][x]["type"])) {
            //           console.log(importedrules[layer][x]["rulebase"])
            objarr = objarr.concat(importedrules[layer][x]["rulebase"])

        } else if ("access-rule" === (importedrules[layer][x]["type"])) {
            //          console.log(importedrules[layer][x])
            objarr = objarr.concat(importedrules[layer][x])
        }
    }
    awruleobj[layer] = objarr
}

//***************************** 
//console.log(awruleobj)
//cp.writeJson(awruleobj, 'aw-flat')
//console.log(Object.keys(awruleobj))

for (layer of layers) {
    let encount = 0
    let discount = 0
    let zerocount = 0
    let hitsLastYear = 0
    let hitsLastSixmonth = 0
    let hitsLastMonth = 0
    let hitsLastSeven = 0

    let createdLastYear = 0
    let createdLastSixmonth = 0
    let createdLastMonth = 0
    let createdLastSeven = 0

    let modifiedLastYear = 0
    let modifiedLastSixmonth = 0
    let modifiedLastMonth = 0
    let modifiedLastSeven = 0

    let adminarray = []
    var counts = {},
        i, value;

    //console.log(awruleobj[layer])

    awruleobj[layer].forEach(element => {
        testdate = element["meta-info"]["last-modify-time"]["posix"]
        if (testdate < lastYear) {
            //console.log("last year");
            modifiedLastYear++
        } else if (testdate < lastSixmonth) {
            //console.log("last hit in 6-12 month");
            modifiedLastSixmonth++
        } else if (testdate < lastMonth) {
            //console.log("last hit last 1-6 months");
            modifiedLastMonth++
        } else if (testdate < lastSeven) {
            //console.log("last hit last 7 days ");
            modifiedLastSeven++
        }

    })

    awruleobj[layer].forEach(element => {
        testdate = element["meta-info"]["creation-time"]["posix"]
        if (testdate < lastYear) {
            //console.log("last year");
            createdLastYear++
        } else if (testdate < lastSixmonth) {
            //console.log("last hit in 6-12 month");
            createdLastSixmonth++
        } else if (testdate < lastMonth) {
            //console.log("last hit last 1-6 months");
            createdLastMonth++
        } else if (testdate < lastSeven) {
            //console.log("last hit last 7 days ");
            createdLastSeven++
        }

    })

    awruleobj[layer].forEach(element => {
        let testelement = element["enabled"]
        if (testelement) encount++
        else discount++
        //console.log(testelement)
    })

    awruleobj[layer].forEach(element => {
        let testelement = element["hits"]["value"]
        // console.log(testelement)
    })

    awruleobj[layer].forEach(element => {
        let testelement = element["meta-info"]["last-modifier"]
        adminarray.push(testelement)
        // console.log(testelement)
    })

    let adminunique = [...new Set(adminarray)];
    for (let i = 0; i < adminarray.length; i++) {
        value = adminarray[i];
        if (typeof counts[value] === "undefined") {
            counts[value] = 1;
        } else {
            counts[value]++;
        }
    }

    awruleobj[layer].forEach(element => {
        //   console.log(element["rule-number"])
        try {
            testdate = element["hits"]["last-date"]["posix"]
            //console.log(element["rule-number"])
            //console.log(element["hits"]["last-date"]["iso-8601"])
            if (testdate < lastYear) {
                //console.log("last year");
                hitsLastYear++
            } else if (testdate < lastSixmonth) {
                //console.log("last hit in 6-12 month");
                hitsLastSixmonth++
            } else if (testdate < lastMonth) {
                //console.log("last hit last 1-6 months");
                hitsLastMonth++
            } else if (testdate < lastSeven) {
                //console.log("last hit last 7 days ");
                hitsLastSeven++
            }
        } catch (error) {
            zerocount++;
            //console.log("zero hits")
        }
    })

    console.log("**********")
    console.log("Layer Name: ", layer)
    console.log("Enabled Rules: ", encount)
    console.log("Disabled Rules: ", discount)
    console.log("Zero Hit Rules: ", zerocount)
    console.log("Admins", counts)
    console.log("**********")
    console.log("Rules used in last 7 days", hitsLastSeven)
    console.log("Rules used in last 30 days", hitsLastMonth)
    console.log("Rules used in last Last Six Months", hitsLastSixmonth)
    console.log("Rules used in last Year", hitsLastYear)
    console.log("**********")
    console.log("Rules created in last 7 days", createdLastSeven)
    console.log("Rules created in last 30 days", createdLastMonth)
    console.log("Rules created in last Last Six Months", createdLastSixmonth)
    console.log("Rules created in last Year", createdLastYear)
    console.log("**********")
    console.log("Rules modified in last 7 days", modifiedLastSeven)
    console.log("Rules modified in last 30 days", modifiedLastMonth)
    console.log("Rules modified in last Last Six Months", modifiedLastSixmonth)
    console.log("Rules modified in last Year", modifiedLastYear)


}



//for (let y in awruleobj[layer]) {
//    console.log(awruleobj[layer][y]["meta-info"]["last-modify-time"]["posix"])
//}