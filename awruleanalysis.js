/** cprest client access for API
 */
'use strict'
const cp = require('./cp')

/**
 * Variable required from auth/mycpauth.json
 * @params {Object} credentials - auth/mycpauth.json
 * @example 
 * create auth/mycpauth.json file
 * {
 *		"user": "apiuser",
 *		"password": "PASSWORD"
 * }
 */
const mycred = require('./auth/mycpauth')

/** 
 * Properties for accessing specific check point rules
 * @typedef {Object} access-rule
 * @property {String} layer Layer that the rule belongs to identified by the name or UID.
 * @property {String} uid Object unique identifier.
 * @property {String} name Object unique name.
 * @property {Number} rule-number Rule number in policy layer. 
 * @property {Boolean} show-hits set to true for rule activity counter
 */

const limit = 500

main()

async function main() {
    cp.startSession(mycred)
        .then(() => getLayerNames())
        .then(layers => awrule(layers))
        .then(awruleobj => analysis(awruleobj))
        .then(() => cp.endSession())
        .catch(cp.endSession)
}

async function getLayerNames() {
    try {
        var mydata = {}
        var mycmd = 'show-access-layers'
        var objdata = {}
        var objarr = []
        mydata.offset = 0
        mydata['details-level'] = 'standard'
        mydata.limit = limit
        console.log('getting layers')
        objdata = await cp.apicall(mydata, mycmd)
        if (!objdata['access-layers']) {
            throw new Error(objdata)
        }
        objarr = objarr.concat(objdata['access-layers'])
        if (objdata.total > objdata.to) {
            while (objdata.total > mydata.offset) {
                console.log('Indexed from ' + objdata.from + ' to ' + objdata.to + ' of ' + objdata.total + ' total objects')
                mydata.offset = Number(objdata.to)
                objdata = await cp.apicall(mydata, mycmd)
                objarr = objarr.concat(objdata['access-layers'])
            }
        }

        // Just need layer names
        let layerarr = []
        objarr.forEach(x => layerarr.push(x.name))
        //console.log(layerarr)

        return layerarr
    } catch (err) {
        console.log('error in getLayers : ' + err)
    }
}

async function awrule(layers) {

    //console.log(layers)
    let awruleobj = {}
    for (let element of layers) {
        let mycmd = "show-access-rulebase"
        let awdata = {}
        let objarr = []
        awdata['name'] = element
        awdata['use-object-dictionary'] = false
        awdata['offset'] = 0
        awdata['show-hits'] = true
        awdata['details-level'] = 'standard'
        awdata.limit = limit

        let awrulebase = await cp.apicall(awdata, mycmd)
        //console.log(awrulebase['rulebase'])
        //console.log(awrulebase.to)
        objarr = objarr.concat(awrulebase['rulebase'])
        //console.log(awrulebase)

        if (awrulebase.total > awrulebase.to) {
            while (awrulebase.total > awdata.offset) {
                console.log('Indexed from ' + awrulebase.from + ' to ' + awrulebase.to + ' of ' + awrulebase.total + ' total objects')
                awdata.offset = Number(awrulebase.to)
                awrulebase = await cp.apicall(awdata, mycmd)
                objarr = objarr.concat(awrulebase['rulebase'])
            }
        }
        awruleobj[element] = objarr
    }
    return (awruleobj)
}

async function analysis(ruleobj) {
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

    let d = new Date();
    let now = d.getTime()
    let msday = 86400000
    let lastYear = (now - (365 * msday))
    let lastSixmonth = (now - (180 * msday))
    let lastMonth = (now - (30 * msday))
    let lastSeven = (now - (7 * msday))
    let testdate = 0
    let layers = (Object.keys(ruleobj))
    let layer = ""
    let awruleobj = {}

    // Let's flatten the rulebase

    for (layer of layers) {
        console.log("Processing Layer: ", layer)
        let objarr = []
        for (let x in ruleobj[layer]) {
            //console.log(importedrules[layer][x]["type"])
            if ("access-section" === (ruleobj[layer][x]["type"])) {
                //           console.log(importedrules[layer][x]["rulebase"])
                objarr = objarr.concat(ruleobj[layer][x]["rulebase"])

            } else if ("access-rule" === (ruleobj[layer][x]["type"])) {
                //          console.log(importedrules[layer][x])
                objarr = objarr.concat(ruleobj[layer][x])
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
        let anypermitcount = 0
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

        //Count when the rule was last modified
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
            let testelement = element["service"][0]["name"]
            //console.log(testelement)
            if (testelement === "Any") {
                let testelement2 = element["action"]["name"]
                if (testelement2 === "Accept") {
                    //console.log("SERVICE ANY AND PERMIT!")
                    anypermitcount++
                }
            }
            // console.log(testelement)
        })

        //Gather all of the admins that made changes
        awruleobj[layer].forEach(element => {
            let testelement = element["meta-info"]["last-modifier"]
            adminarray.push(testelement)
            // console.log(testelement)
        })

        //set "counts" to be the admins and the number of rules they changed based on above array.
        for (let i = 0; i < adminarray.length; i++) {
            value = adminarray[i];
            if (typeof counts[value] === "undefined") {
                counts[value] = 1;
            } else {
                counts[value]++;
            }
        }



        console.log("**********")
        console.log("Layer Name: ", layer)
        console.log("Enabled Rules: ", encount)
        console.log("Disabled Rules: ", discount)
        console.log("Zero Hit Rules: ", zerocount)
        console.log("Service any with permit Rules: ", anypermitcount)
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
}