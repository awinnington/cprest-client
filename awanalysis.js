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
let testdate = 1560742571250


// if (testdate < lastSeven) console.log("One")
// else if (testdate < lastMonth) console.log("Two")
// else if (testdate < lastSixmonth) console.log("Three")
// else console.log("Four")

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
let encount = 0
let discount = 0

//console.log(Object.keys(awruleobj))
for (layer of layers) {
    //console.log(awruleobj[layer])
    awruleobj[layer].forEach(element => {
        testdate = element["meta-info"]["last-modify-time"]["posix"]
        if (testdate < lastYear) console.log("last year")
        else if (testdate < lastSixmonth) console.log("last modify in 6-12 month")
        else if (testdate < lastMonth) console.log("last modify last 1-6 months")
        else if (testdate < lastSeven) console.log("last modify last 7 days ")

    })

    awruleobj[layer].forEach(element => {
        testdate = element["meta-info"]["creation-time"]["posix"]
        if (testdate < lastYear) console.log("last year")
        else if (testdate < lastSixmonth) console.log("last created in 6-12 month")
        else if (testdate < lastMonth) console.log("last created last 1-6 months")
        else if (testdate < lastSeven) console.log("last created last 7 days ")

    })

    awruleobj[layer].forEach(element => {
        let testelement = element["enabled"]
        if (testelement) encount++
        else discount++
        console.log(testelement)
    })

    awruleobj[layer].forEach(element => {
        let testelement = element["hits"]["value"]
        console.log(testelement)
    })

    awruleobj[layer].forEach(element => {
        console.log(element["rule-number"])
        try {
            testdate = element["hits"]["last-date"]["posix"]
            //console.log(element["rule-number"])
            //console.log(element["hits"]["last-date"]["iso-8601"])
            if (testdate < lastYear) console.log("last year")
            else if (testdate < lastSixmonth) console.log("last hit in 6-12 month")
            else if (testdate < lastMonth) console.log("last hit last 1-6 months")
            else if (testdate < lastSeven) console.log("last hit last 7 days ")
        } catch(error) {
            console.log("zero hits")
        }
    })

}

console.log("**********")
console.log(encount)
console.log(discount)

//for (let y in awruleobj[layer]) {
//    console.log(awruleobj[layer][y]["meta-info"]["last-modify-time"]["posix"])
//}