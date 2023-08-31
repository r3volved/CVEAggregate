const { writeFileSync, readFileSync, existsSync } = require('fs')
const path = require('path')

const diffInDays = (date1, date2 = Date.now()) => {
    const last = new Date(date1)
    const now  = new Date(date2)
    const Difference_In_Time = now.getTime() - last.getTime()
    const Difference_In_Days = Difference_In_Time / (1000 * 3600 * 24)
    return Difference_In_Days
}

class CVEAggregate { 
    #urlCVES = "https://cve.mitre.org/data/downloads/allitems.csv"
    #urlCISA = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    #urlEPSS = "https://api.first.org/data/v1/epss"
    #urlCVSS = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    #severityRatings = [
        { name: "None", bottom: 0.0, top: 0.0 }, 
        { name: "Low", bottom: 0.1, top: 3.9 }, 
        { name: "Medium", bottom: 4.0, top: 6.9 }, 
        { name: "High", bottom: 7.0, top: 8.9 }, 
        { name: "Critical", bottom: 9.0, top: 10.0 }
    ]

    #cvss2 = {
        vectorRegex: /((AV:[NAL]|AC:[LHM]|Au:[MSN]|[CIA]:[NPC]|E:[ND|U|POC|F|H]{1,3}|RL:[ND|OF|TF|W|U]{1,2}|RC:[ND|UC|UR|C]{1,2}|CDP:[ND|N|L|LM|MH|H]{1,2}|TD:[ND|N|L|M|H]{1,2}|CR:[ND|L|M|H]{1,2}|IR:[ND|L|M|H]{1,2}|AR:[ND|L|M|H]{1,2})\/)*(AV:[NAL]|AC:[LHM]|Au:[MSN]|[CIA]:[NPC]|E:[ND|U|POC|F|H]{1,3}|RL:[ND|OF|TF|W|U]{1,2}|RC:[ND|UC|UR|C]{1,2}|CDP:[ND|N|L|LM|MH|H]{1,2}|TD:[ND|N|L|M|H]{1,2}|CR:[ND|L|M|H]{1,2}|IR:[ND|L|M|H]{1,2}|AR:[ND|L|M|H]{1,2})/,
        vectorPattern: /[A-Za-z]{1,3}:[A-Za-z]{1,3}/ig,
        exploitabilityCoefficient: 8.22,
        baseKeys: ["AV","AC","Au","C","I","A"],
        temporalKeys: ["E","RL","RC"],
        environmentKeys: ["CDP","TD","CR","IR","AR"],
        weight: {
            AV: { L:0.395, A:0.646, N:1.0 },
            AC: { H:0.35, M:0.61, L:0.71 },
            Au: { M:0.45, S:0.56, N:0.704 },
            C:  { N:0, P:0.275, C:0.660 },
            I:  { N:0, P:0.275, C:0.660 },
            A:  { N:0, P:0.275, C:0.660 },
    
            E:  { ND:1, U:0.85, POC:0.9, F:0.95, H:1 },
            RL: { ND:1, OF:0.97, TF:0.9, W:0.95, U:1 },
            RC: { ND:1, UC:0.9, UR:0.95, C:1 },
    
            CDP:{ ND:0, N:0, L:0.1, LM:0.3, MH:0.4, H:0.5 },
            TD: { ND:1, N:0, L:0.25, M:0.75, H:1 },
            CR: { ND:1, L:0.5, M:1, H:1.51 },
            IR: { ND:1, L:0.5, M:1, H:1.51 },
            AR: { ND:1, L:0.5, M:1, H:1.51 },
        }
    }

    #cvss3 = {
        vectorRegex: /CVSS:3(\.\d){0,1}\/((AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])\/)*(AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])/,
        exploitabilityCoefficient: 8.22,
        scopeCoefficient: 1.08,
        weight: {
            AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
            AC: { H: 0.44, L: 0.77 },
            PR: { 
                U: { N: 0.85, L: 0.62, H: 0.27 }, 
                C: { N: 0.85, L: 0.68, H: 0.5 }
            },
            UI: { N: 0.85, R: 0.62 },
            S: { U: 6.42, C: 7.52 },
            CIA: { N: 0, L: 0.22, H: 0.56 },
            E: { X: 1, U: 0.91, P: 0.94, F: 0.97, H: 1 },
            RL: { X: 1, O: 0.95, T: 0.96, W: 0.97, U: 1 },
            RC: { X: 1, U: 0.92, R: 0.96, C: 1 },
            CIAR: { X: 1, L: 0.5, M: 1, H: 1.5 }
        }
        
    }

    constructor(filepath, verbose = false){
        this.filepath    = filepath?.length ? filepath : path.join(__dirname, 'cves.json')
        this.verbose     = verbose
        this.cves        = {}
        this.lastUpdated = null
        this.cvesUpdated = null
        this.cisaUpdated = null
        this.epssUpdated = null
        this.cvssUpdated = null
        this.lastCount   = null
        this.daysdiff    = 0.1    //Skip epss and cvss update if less than this many days since last update
        this.load()
    }

    //Log to console
    //- Array of lines will update
    //- Error will dump stack
    //- Any other value will new line
    log(lines) {
        if( !this.verbose ) return
        if( lines === undefined ) return
        if( Array.isArray(lines) ) {
            if( this.logging ) {
                process.stdout.moveCursor(0, -1*(lines.length))
                process.stdout.clearLine(0)
                process.stdout.cursorTo(0)
            }
            process.stdout.write(lines.join('\n')+'\n')
            this.logging = true
        } else if( lines instanceof Error ) {
            this.logging = false
            console.error(lines)
        } else {
            this.logging = false
            console.log(lines)        
        }
    }

    //Dump internal details
    dump() {
        return {
            lastUpdated:this.lastUpdated,
            cvesUpdated:this.cvesUpdated,
            cisaUpdated:this.cisaUpdated,
            epssUpdated:this.epssUpdated,
            cvssUpdated:this.cvssUpdated,
            lastCount:Object.keys(this.cves).length,
            cves:this.cves,
        }
    }

    //Save current cves to filepath
    save() {
        this.lastUpdated = (new Date()).toISOString()
        writeFileSync(this.filepath, JSON.stringify(this.dump()), 'utf8')
    }

    //Load cves from a filepath
    load() {
        try { 
            if( !existsSync(this.filepath) ) throw new Error('No cve list')
            const json = JSON.parse(readFileSync(this.filepath, 'utf8')) 
            this.cves        = json.cves        || this.cves
            this.lastUpdated = json.lastUpdated || this.lastUpdated
            this.lastCount   = json.lastCount   || this.lastCount
            this.cvesUpdated = json.cvesUpdated || this.cvesUpdated
            this.cisaUpdated = json.cisaUpdated || this.cisaUpdated
            this.epssUpdated = json.epssUpdated || this.epssUpdated
            this.cvssUpdated = json.cvssUpdated || this.cvssUpdated
        } catch(e) { 
            this.cves        = this.cves        || {}
            this.lastUpdated = this.lastUpdated || null
            this.lastCount   = this.lastCount   || null
            this.cvesUpdated = this.cvesUpdated || null
            this.cisaUpdated = this.cisaUpdated || null
            this.epssUpdated = this.epssUpdated || null
            this.cvssUpdated = this.cvssUpdated || null
        }
        this.newCVES  = new Set()
        this.newCISA  = new Set()
        this.newEPSS  = new Set()
        this.newCVSS2 = new Set()
        this.newCVSS3 = new Set()
    }

    //Report update details since last load
    report(reportZero) {
        if( reportZero || this.newCVES.size )  this.log(`Found ${this.newCVES.size.toLocaleString()} new CVEs`)
        if( reportZero || this.newCISA.size )  this.log(`Found ${this.newCISA.size.toLocaleString()} new CISA entries`)
        if( reportZero || this.newEPSS.size )  this.log(`Found ${this.newEPSS.size.toLocaleString()} new EPSS scores`)
        if( reportZero || this.newCVSS2.size ) this.log(`Found ${this.newCVSS2.size.toLocaleString()} new CVSSv2 vectors`)
        if( reportZero || this.newCVSS3.size ) this.log(`Found ${this.newCVSS3.size.toLocaleString()} new CVSSv3 vectors`)
        
        if( reportZero || this.newCVES.size || this.newCISA.size || this.newEPSS.size || this.newCVSS2.size || this.newCVSS3.size )
            this.log(`-`.repeat(30))

        const data = this.dump()

        data.newCVES = this.newCVES
        data.newCISA = this.newCISA
        data.newEPSS = this.newEPSS
        data.newCVSS2 = this.newCVSS2
        data.newCVSS3 = this.newCVSS3
        data.totalCVES = Object.keys(this.cves).length
        data.totalCISA = Object.values(this.cves).filter(i => i.cisa).length
        data.totalEPSS = Object.values(this.cves).filter(i => i.epss).length
        data.totalCVSS = Object.values(this.cves).filter(i => i.cvss2 || i.cvss3).length

        this.log(`Total CVEs:         ${data.totalCVES.toLocaleString()}`)
        this.log(`Total CISA entries: ${data.totalCISA.toLocaleString()}`)
        this.log(`Total EPSS scores:  ${data.totalEPSS.toLocaleString()}`)
        this.log(`Total CVSS vectors: ${data.totalCVSS.toLocaleString()}`)
        
        return data
    }

    
    //Get the severity rating of a cvss score
    severityRating(score) {
        const severityRatingLength = this.#severityRatings.length
        const validatedScore = Number(score)
        if( isNaN(validatedScore) ) 
            return validatedScore

        for( let i = 0; i < severityRatingLength; i++ ) {
            if( score >= this.#severityRatings[i].bottom && score <= this.#severityRatings[i].top ) 
                return this.#severityRatings[i].name
        }

        return undefined
    }

    //Calculate a CVSS scoring from a v2 vector
    calculateCVSS2Vector(vectorString) {
        if( !this.#cvss2.vectorRegex.test(vectorString) ) 
            throw new Error("Malformed V2 Vector String")
        
        const vectorMatches = vectorString.match(this.#cvss2.vectorPattern);
        const metricValues = vectorMatches.reduce((acc,m) => {
            const [key, val] = m.split(':')
            if( key && val ) acc[key] = val
            return acc
        },{})
        
        this.#cvss2.temporalKeys.concat( this.#cvss2.environmentKeys ).forEach(key => metricValues[key] = metricValues[key] || "ND")

        const value = (key) => this.#cvss2.weight[key][metricValues[key]]

        const impact = 10.41 * (1 - (1 - value('C')) * (1 - value("I")) * (1 - value('A')))
        const exploitability = this.#cvss2.exploitabilityCoefficient * value("AC") * value("Au") * value("AV")
        const baseScore = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * (impact === 0 ? 0 : 1.176)
        const temporalScore = baseScore * value("E") * value("RL") * value("RC")
        const modifiedImpact   = Math.min(10, 10.41 * (1 - (1 - value("C") * value("CR")) * (1 - value("I") * value("IR")) * (1 - value("A") * value("AR"))))
        const modifiedBase     = ((0.6 * modifiedImpact) + (0.4 * exploitability) - 1.5) * (modifiedImpact === 0 ? 0 : 1.176)
        const modifiedTemporal = modifiedBase * value("E") * value("RL") * value("RC")
        const envScore  = (modifiedTemporal + (10 - modifiedTemporal) * value("CDP")) * value("TD")

        return {
            baseMetricScore: Number(baseScore.toFixed(1)),
            baseSeverity: this.severityRating(baseScore.toFixed(1)),
            baseImpact: impact,
            baseExploitability: exploitability,
            temporalMetricScore: Number(temporalScore.toFixed(1)),
            temporalSeverity: this.severityRating(temporalScore.toFixed(1)),
            environmentalMetricScore: Number(envScore.toFixed(1)),
            environmentalSeverity: this.severityRating(envScore.toFixed(1)),
            environmentalModifiedImpact: modifiedImpact,
            vectorString,
            version:"CVSS:2"
        }
    }

    //Calculate a CVSS scoring from a v3.x vector
    calculateCVSS3Vector(vectorString) {
        if( !this.#cvss3.vectorRegex.test(vectorString) ) 
            throw new Error("Malformed V3.x Vector String")
        
        const version = vectorString.match(/CVSS:3(\.\d){0,1}/)[0]
        const metricNameValue = vectorString.substring(version.length).split("/")
        const metricValues = {}

        const roundUp = function (input) {
            const int_input = Math.round(input * 100000)
            return int_input % 10000 === 0
                ? int_input / 100000
                : (Math.floor(int_input / 10000) + 1) / 10
        }
    
        for( const i in metricNameValue ) {
            if( !metricNameValue.hasOwnProperty(i) ) continue
            const singleMetric = metricNameValue[i].split(":")
            metricValues[singleMetric[0]] = singleMetric[1]
        }

        const {
            AV = null, 
            AC = null, 
            PR = null, 
            UI = null, 
            S = null, 
            C = null, 
            I = null, 
            A = null, 
            E = 'X', 
            RL = 'X', 
            RC = 'X', 
            CR = 'X',
            IR = 'X', 
            AR = 'X', 
            MAV = 'X', 
            MAC = 'X', 
            MPR = 'X', 
            MUI = 'X',
            MS = 'X', 
            MC = 'X', 
            MI = 'X', 
            MA = 'X'
        } = metricValues
        
        const metricWeightAV  = this.#cvss3.weight.AV[AV]
        const metricWeightAC  = this.#cvss3.weight.AC[AC]
        const metricWeightPR  = this.#cvss3.weight.PR[S][PR]
        const metricWeightUI  = this.#cvss3.weight.UI[UI]
        const metricWeightS   = this.#cvss3.weight.S[S]
        const metricWeightC   = this.#cvss3.weight.CIA[C]
        const metricWeightI   = this.#cvss3.weight.CIA[I]
        const metricWeightA   = this.#cvss3.weight.CIA[A]
        const metricWeightE   = this.#cvss3.weight.E[E]
        const metricWeightRL  = this.#cvss3.weight.RL[RL]
        const metricWeightRC  = this.#cvss3.weight.RC[RC]
        const metricWeightCR  = this.#cvss3.weight.CIAR[CR]
        const metricWeightIR  = this.#cvss3.weight.CIAR[IR]
        const metricWeightAR  = this.#cvss3.weight.CIAR[AR]
        const metricWeightMAV = this.#cvss3.weight.AV[MAV !== "X" ? MAV : AV]
        const metricWeightMAC = this.#cvss3.weight.AC[MAC !== "X" ? MAC : AC]
        const metricWeightMPR = this.#cvss3.weight.PR[MS !== "X" ? MS : S][MPR !== "X" ? MPR : PR]
        const metricWeightMUI = this.#cvss3.weight.UI[MUI !== "X" ? MUI : UI]
        const metricWeightMS  = this.#cvss3.weight.S[MS !== "X" ? MS : S]
        const metricWeightMC  = this.#cvss3.weight.CIA[MC !== "X" ? MC : C]
        const metricWeightMI  = this.#cvss3.weight.CIA[MI !== "X" ? MI : I]
        const metricWeightMA  = this.#cvss3.weight.CIA[MA !== "X" ? MA : A]

        const iss = (1 - ((1 - metricWeightC) * (1 - metricWeightI) * (1 - metricWeightA)))
        const impact = S === 'U' 
            ? metricWeightS * iss
            : metricWeightS * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)

        const exploitability = this.#cvss3.exploitabilityCoefficient * metricWeightAV * metricWeightAC * metricWeightPR * metricWeightUI
        const baseScore = impact <= 0 ? 0 : S === 'U'
            ? roundUp(Math.min((exploitability + impact), 10))
            : roundUp(Math.min(this.#cvss3.scopeCoefficient * (exploitability + impact), 10))

        const temporalScore = roundUp(baseScore * metricWeightE * metricWeightRL * metricWeightRC)
        const miss = Math.min(1 - ((1 - metricWeightMC * metricWeightCR) * (1 - metricWeightMI * metricWeightIR) * (1 - metricWeightMA * metricWeightAR)), 0.915)
        const modifiedImpact = MS === "U" || (MS === "X" && S === "U")
            ? metricWeightMS * miss
            : metricWeightMS * (miss - 0.029) - 3.25 * Math.pow(miss * 0.9731 - 0.02, 13)

        const modifiedExploitability = this.#cvss3.exploitabilityCoefficient * metricWeightMAV * metricWeightMAC * metricWeightMPR * metricWeightMUI
        const envScore = modifiedImpact <= 0 ? 0 : MS === "U" || (MS === "X" && S === "U") 
            ? roundUp(roundUp(Math.min((modifiedImpact + modifiedExploitability), 10)) * metricWeightE * metricWeightRL * metricWeightRC)
            : roundUp(roundUp(Math.min(this.#cvss3.scopeCoefficient * (modifiedImpact + modifiedExploitability), 10)) * metricWeightE * metricWeightRL * metricWeightRC)
        
        return {
            baseMetricScore: Number(baseScore.toFixed(1)),
            baseSeverity: this.severityRating(baseScore.toFixed(1)),
            baseImpact: impact,
            baseExploitability: exploitability,
            temporalMetricScore: Number(temporalScore.toFixed(1)),
            temporalSeverity: this.severityRating(temporalScore.toFixed(1)),
            environmentalMetricScore: Number(envScore.toFixed(1)),
            environmentalSeverity: this.severityRating(envScore.toFixed(1)),
            environmentalModifiedImpact: modifiedImpact,
            vectorString,
            version
        }

    }

    //Calculate a CVSS scoring from a vector string 
    //Note this just routes to applicable calculation
    calculateCVSSVector(vectorString) {
        return !vectorString.startsWith('CVSS:3') || vectorString.match(/Au:[MSN]/) 
            ? this.calculateCVSS2Vector(vectorString)
            : this.calculateCVSS3Vector(vectorString)
    }

    //Return true if any cve is in CISA
    getCISA(...cveIds) {
        for(const cveId of cveIds) {
            if( this.cves[cveId]?.cisa?.length ) return true
        }
        return false
    }

    //Map CISA by cveId
    mapCISA(...cveIds) { 
        return cveIds.reduce((map,cveId) => {
            map[cveId] = this.cves[cveId]?.cisa || null
            return map
        },{})
    }
    
    //Return the scaled epss score of all cves
    getEPSS(...cveIds) {
        return (1 - cveIds.map(cveId => this.cves[cveId]?.epss || 0).filter(v => v).reduce((p,v) => p * (1-v),1))
    }

    //Map EPSS by cveId
    mapEPSS(...cveIds) { 
        return cveIds.reduce((map,cveId) => {
            map[cveId] = this.cves[cveId]?.epss || 0
            return map
        },{})
    }

    //Return the max cvss score of all cves
    getCVSS(...cveIds) {
        return cveIds.reduce((max,cveId) => {
            try {
                const score = this.calculateCVSSVector(this.cves[cveId]?.cvss3 || this.cves[cveId]?.cvss2)
                return Math.max(max, score.environmentalMetricScore)
            } catch(e) {
                return max
            }
        },0)
    }

    //Map CVSS by cveId (v3 if exists, else v2)
    mapCVSS(...cveIds) { 
        return cveIds.reduce((map,cveId) => {
            map[cveId] = this.cves[cveId]?.cvss3 || this.cves[cveId]?.cvss2 || null
            return map
        },{})
    }

    //Parse a line from the CVE-CSV - looking for CVE ids
    parseCSVLine(line) {
        if( !line.length ) return
        
        const cveId = line?.match?.(/^(CVE-\d{4}-\d{4,})\s*,/)?.[1]
        if( !cveId?.length ) return
        if( !(cveId in this.cves) ) {
            this.cves[cveId] = { cisa:null, epss:0, cvss2:null, cvss3:null }
            this.newCVES.add(cveId)
        }
    }

    //Parse the due date from CISA entry
    parseCISA(item) {
        const cveId = item?.cveID
        if( !cveId?.length ) return
        if( !(cveId in this.cves) ) {
            this.cves[cveId] = { cisa:null, epss:0, cvss2:null, cvss3:null }
            this.newCVES.add(cveId)
        }

        if( this.cves[cveId].cisa === item?.dueDate ) 
            return //Already the same

        if( !this.cves[cveId].cisa ) {
            this.newCISA.add(cveId)
        }
        this.cves[cveId].cisa = item?.dueDate
    }
    
    //Parse the epss score from first.org response item
    parseEPSS(item) {
        const cveId = item?.cve
        if( !cveId?.length ) return
        if( !(cveId in this.cves) ) {
            this.cves[cveId] = { cisa:null, epss:0, cvss2:null, cvss3:null }
            this.newCVES.add(cveId)
        }

        if( this.cves[cveId].epss === item.epss ) 
            return //Already the same

        if( !this.cves[cveId].epss ) {
            this.newEPSS.add(cveId)
        }
        this.cves[cveId].epss = Number(item.epss)
    }

    //Parse the cvss vectors from nist.gov response item
    parseCVSS(item) {
        const cveId = item?.cve?.id
        if( !cveId?.length ) return
        if( !(cveId in this.cves) ) {
            this.cves[cveId] = { cisa:null, epss:0, cvss2:null, cvss3:null }
            this.newCVES.add(cveId)
        }

        const { cvssMetricV2, cvssMetricV31 } = item?.cve?.metrics || {}

        const v2vector = cvssMetricV2?.[0]?.cvssData?.vectorString
        if( v2vector?.length && this.cves[cveId].cvss2 !== v2vector ) {
            if( !this.cves[cveId].cvss2 ) this.newCVSS2.add(cveId)
            this.cves[cveId].cvss2 = v2vector
        }

        const v3vector = cvssMetricV31?.[0]?.cvssData?.vectorString
        if( v3vector?.length && this.cves[cveId].cvss3 !== v3vector ) {
            if( !this.cves[cveId].cvss3 ) this.newCVSS3.add(cveId)
            this.cves[cveId].cvss3 = v3vector
        }
    }

    //Stream the CVE-CSV from mitre.org and extract new entries
    update_cves (feedback=[], index=0) {
        if( this.cvesUpdated?.length && diffInDays(this.cvesUpdated) < this.daysdiff ) 
            return Promise.resolve(feedback[index] = `Updating CVEs ... [skip]`)

        const https    = require('node:https')
        const readline = require('node:readline')
        const cancelRequest = new AbortController()
        return new Promise((resolve, reject) => {
            https.get(this.#urlCVES, { signal: cancelRequest.signal }, (res) => {
                const lastModified = res.headers['last-modified']
                const lastUpdated  = this.cvesUpdated
                if( lastModified?.length && new Date(lastModified) <= new Date(lastUpdated) ) {
                    feedback[index] = `Updating CVEs ... [skip]`
                    cancelRequest.abort()
                    return reject()
                }
                
                let len = 0
                feedback[index] = `Updating CVEs ... `
                const size = Number(res.headers['content-length'])
                const readStream  = readline.createInterface({ input:res })
                readStream.on('close', resolve)
                readStream.on('error', reject)
                readStream.on("line", line => this.parseCSVLine(line))
                res.on('data', (data) => {
                    const pct = ((len += data.length) / size * 100).toFixed(1)
                    feedback[index] = `Updating CVEs ... ${pct}%`
                })

            })
        })
        .then(() => {
            feedback[index] = `Updating CVEs ... 100.0%`
            this.cvesUpdated = (new Date()).toISOString()
        })
        .catch(e => this.log(e))
        .finally(() => this.save())
    }

    //Fetch the CISA-KEV from cisa.gov and extract new entries
    update_cisa (feedback=[], index=0) {
        if( this.cisaUpdated?.length && diffInDays(this.cisaUpdated) < this.daysdiff ) 
            return Promise.resolve(feedback[index] = `Updating CISA ... [skip]`)

        return new Promise(async (resolve, reject) => {

            feedback[index] = `Updating CISA ... `
            const kev = await fetch(this.#urlCISA)
                .then(res => res.json())
                .catch(e => this.log(e))
            
            const { count = 0, vulnerabilities = [] } = kev || {}
            kev?.vulnerabilities?.forEach((item,i) => {
                let pct = (i / (count || 1) * 100).toFixed(1)
                feedback[index] = `Updating CISA ... ${pct}%`
                this.parseCISA(item)
            })
            resolve()        

        })
        .then(() => {
            feedback[index] = `Updating CISA ... 100.0%`
            this.cisaUpdated = (new Date()).toISOString()
        })
        .catch(e => this.log(e))
        .finally(() => this.save())
    }
    
    //Fetch the EPSS scores from first.org and extract new entries
    update_epss (feedback=[], index=0) {
        if( this.epssUpdated?.length && diffInDays(this.epssUpdated) < this.daysdiff ) 
            return Promise.resolve(feedback[index] = `Updating EPSS ... [skip]`)
        
        return new Promise(async (resolve, reject) => {            
            const lastUpdated  = this.epssUpdated
            const daysLimit = (() => {
                if( !lastUpdated ) return ''
                const last = new Date(lastUpdated)
                const now  = new Date()
                const Difference_In_Time = now.getTime() - last.getTime()
                const Difference_In_Days = Difference_In_Time / (1000 * 3600 * 24)
                return `&days=${Math.ceil(Difference_In_Days)}`
            })()

            feedback[index] = `Updating EPSS ... `
            const firstBatch = await fetch(`${this.#urlEPSS}?envelope=true${daysLimit}`)
                .then(res => res.json())
                .catch(e => this.log(e))
    
            const { total = 1, data = [] } = firstBatch || {}
                
            let offset = data?.length || total || 1
            let pct = (offset / (total || 1) * 100).toFixed(1)
    
            feedback[index] = `Updating EPSS ... ${pct}%`
            data?.forEach?.(item => this.parseEPSS(item))
    
            let fails = 0
            while(total > offset) {
                const loopBatch = await fetch(`${this.#urlEPSS}?envelope=true&offset=${offset}${daysLimit}`)
                    .then(res => res.status < 400 ? res.json() : null)
                    .catch(e => this.log(e))
    
                if( !loopBatch?.data ) {
                    //Failed more than 5 times
                    if( ++fails > 5 ) break
                    feedback[index] = `Updating EPSS ... ${pct}% [Fetch failure (${fails})]`
                    //Failed - wait 5 seconds and try again
                    await new Promise(done => setTimeout(() => done(), 5000*fails))
                    continue
                } else { 
                    fails = 0
                    offset += loopBatch.data.length || 0
                    pct = (offset / (total || 1) * 100).toFixed(1)   
                    feedback[index] = `Updating EPSS ... ${pct}% ${' '.repeat(20)}`
                    loopBatch.data?.forEach?.(item => this.parseEPSS(item))                
                }
    
                if( loopBatch.data.length < loopBatch.limit ) break
            }
            resolve()        
        })
        .then(() => {
            feedback[index] = `Updating EPSS ... 100.0%`
            this.epssUpdated = (new Date()).toISOString()
        })
        .catch(e => this.log(e))
        .finally(() => this.save())
    }

    //Fetch the CVSS vectors from nist.gov and extract new entries
    update_cvss (feedback=[], index=0) {
        if( this.cvssUpdated?.length && diffInDays(this.cvssUpdated) < this.daysdiff ) 
            return Promise.resolve(feedback[index] = `Updating CVSS ... [skip]`)

        return new Promise(async (resolve, reject) => {
            const lastUpdated  = this.cvssUpdated
            const daysLimit = (() => {
                if( !lastUpdated ) return ''
                const lastModStartDate = lastUpdated.split('.')[0]+"Z"
                const lastModEndDate   = new Date().toISOString().split('.')[0]+"Z"
                return `&lastModStartDate=${lastModStartDate}&lastModEndDate=${lastModEndDate}`
            })()

            feedback[index] = `Updating CVSS ... `
            const firstBatch = await fetch(`${this.#urlCVSS}?startIndex=0&${daysLimit}`)   
                .then(res => res.json())
                .catch(e => this.log(e))

            const { resultsPerPage = 0, totalResults = 0, vulnerabilities = [] } = firstBatch || {}
                
            let offset = vulnerabilities?.length || totalResults || 1
            let pct = (offset / (totalResults || 1) * 100).toFixed(1)
    
            feedback[index] = `Updating CVSS ... ${pct}%`
            vulnerabilities?.forEach?.(item => this.parseCVSS(item))
    
            let fails = 0
            while(totalResults > offset) {
                await new Promise(done => setTimeout(() => done(), 4000)) //Fetch throttle
    
                const loopBatch = await fetch(`${this.#urlCVSS}?startIndex=${offset}${daysLimit}`)
                    .then(res => res.status < 400 ? res.json() : null)
                    .catch(e => this.log(e))
    
                if( !loopBatch?.vulnerabilities ) {
                    //Failed more than 5 times
                    if( ++fails > 5 ) break
                    feedback[index] = `Updating CVSS ... ${pct}% [Fetch failure (${fails})]`
                    //Failed - throttle and try again
                    await new Promise(done => setTimeout(() => done(), 5000*fails))
                    continue
                } else { 
                    fails = 0
                    offset += loopBatch.vulnerabilities.length || 0
                    pct = (offset / (totalResults || 1) * 100).toFixed(1)
                    feedback[index] = `Updating CVSS ... ${pct}% ${' '.repeat(20)}`
                    loopBatch.vulnerabilities?.forEach?.(item => this.parseCVSS(item))                
                }
    
                if( loopBatch.vulnerabilities.length < resultsPerPage ) break
            }
            resolve()        
        })
        .then(() => {
            feedback[index] = `Updating CVSS ... 100.0%`
            this.cvssUpdated = (new Date()).toISOString()
        })
        .catch(e => this.log(e))
        .finally(() => this.save())
    }
    
    //Build with full CVE list
    async build() {
        const feedback = new Array(4).fill('...')
        const interval = setInterval(() => this.log(feedback), 1000)
        return Promise.all([
            this.update_cves(feedback, 0),
            this.update_cisa(feedback, 1),
            this.update_epss(feedback, 2),
            this.update_cvss(feedback, 3),
        ]).finally(() => {
            clearInterval(interval)
            this.log(feedback)            
        })
    }

    //Build with only applicable CVEs
    async update() {
        const feedback = new Array(3).fill('...')
        const interval = setInterval(() => this.log(feedback), 1000)
        return Promise.all([
            this.update_cisa(feedback, 0),
            this.update_epss(feedback, 1),
            this.update_cvss(feedback, 2),
        ]).finally(() => {
            clearInterval(interval)
            this.log(feedback)
        })
    }
}

module.exports = CVEAggregate

