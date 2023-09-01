class CVSS2 {
    #vectorRegex = /((AV:[NAL]|AC:[LHM]|Au:[MSN]|[CIA]:[NPC]|E:[ND|U|POC|F|H]{1,3}|RL:[ND|OF|TF|W|U]{1,2}|RC:[ND|UC|UR|C]{1,2}|CDP:[ND|N|L|LM|MH|H]{1,2}|TD:[ND|N|L|M|H]{1,2}|CR:[ND|L|M|H]{1,2}|IR:[ND|L|M|H]{1,2}|AR:[ND|L|M|H]{1,2})\/)*(AV:[NAL]|AC:[LHM]|Au:[MSN]|[CIA]:[NPC]|E:[ND|U|POC|F|H]{1,3}|RL:[ND|OF|TF|W|U]{1,2}|RC:[ND|UC|UR|C]{1,2}|CDP:[ND|N|L|LM|MH|H]{1,2}|TD:[ND|N|L|M|H]{1,2}|CR:[ND|L|M|H]{1,2}|IR:[ND|L|M|H]{1,2}|AR:[ND|L|M|H]{1,2})/
    #vectorPattern = /[A-Za-z]{1,3}:[A-Za-z]{1,3}/ig

    constructor(options={}) {
        this.version = options.version || "CVSS:2"
        this.exploitabilityCoefficient = options.exploitabilityCoefficient || 8.22
        this.baseKeys = options.baseKeys || ["AV","AC","Au","C","I","A"]
        this.temporalKeys = options.temporalKeys || ["E","RL","RC"]
        this.environmentKeys = options.environmentKeys || ["CDP","TD","CR","IR","AR"]
        this.weight = {
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
        this.severityRatings = options.severityRatings || [
            { name: "None", bottom: 0.0, top: 0.0 }, 
            { name: "Low", bottom: 0.1, top: 3.9 }, 
            { name: "Medium", bottom: 4.0, top: 6.9 }, 
            { name: "High", bottom: 7.0, top: 8.9 }, 
            { name: "Critical", bottom: 9.0, top: 10.0 }
        ]

        this.metricKeys = this.baseKeys.concat( this.temporalKeys ).concat( this.environmentKeys )
        this.metricNames = {
            AV:  'Attack Vector',
            AC:  'Attack Complexity',
            Au:  'Authentication',
            C:   'Confidentiality',
            I:   'Integrity',
            A:   'Availability',
            E:   'Exploitability',
            RL:  'Remediation Level',
            RC:  'Report Confidence',
            CDP: 'Collateral Damage Potential',
            TD:  'Target Distribution',
            CR:  'Confidentiality Requirement',
            IR:  'Integrity Requirement',
            AR:  'Availability Requirement',
        }
        this.metricValues = {
            AV:   { N: "NETWORK", A: "ADJACENT_NETWORK", L: "LOCAL" },
            AC:   { H: "HIGH", M: "MEDIUM", L: "LOW" },
            Au:   { N: "NONE", S: "SINGLE", M: "MULTIPLE" },
            C:    { N: "NONE", P: "PARTIAL", C: "COMPLETE" },
            I:    { N: "NONE", P: "PARTIAL", C: "COMPLETE" },
            A:    { N: "NONE", P: "PARTIAL", C: "COMPLETE" },            
            E:    { ND: "NOT_DEFINED", U: "UNPROVEN", POC: "PROOF_OF_CONCEPT", F: "FUNCTIONAL", H: "HIGH" },
            RL:   { ND: "NOT_DEFINED", OF: "OFFICIAL_FIX", TF: "TEMPORARY_FIX", W: "WORKAROUND", U: "UNAVAILABLE" },
            RC:   { ND: "NOT_DEFINED", UC: "UNCONFIRMED", UR: "UNCORROBORATED", C: "CONFIRMED" },
            CDP:  { ND: "NOT_DEFINED", N: "NONE", L: "LOW", LM: "LOW_MEDIUM", M: "MEDIUM", H: "HIGH" },
            TD:   { ND: "NOT_DEFINED", N: "NONE", L: "LOW", M: "MEDIUM", H: "HIGH" },
            CR:   { ND: "NOT_DEFINED", L: "LOW", M: "MEDIUM", H: "HIGH" },
            IR:   { ND: "NOT_DEFINED", L: "LOW", M: "MEDIUM", H: "HIGH" },
            AR:   { ND: "NOT_DEFINED", L: "LOW", M: "MEDIUM", H: "HIGH" },
        }
    }

    error(reason) {
        return {
            baseMetricScore: 0,
            baseSeverity: null,
            baseImpact: 0,
            baseExploitability: 0,
            temporalMetricScore: 0,
            temporalSeverity: null,
            environmentalMetricScore: 0,
            environmentalSeverity: null,
            environmentalModifiedImpact: 0,
            vectorValues:{},
            vectorString:reason,
            version:this.version
        }
    }

    severityRating(score) {
        const severityRatingLength = this.severityRatings.length
        const validatedScore = Number(score)
        if( isNaN(validatedScore) ) 
            return validatedScore

        for( let i = 0; i < severityRatingLength; i++ ) {
            if( score >= this.severityRatings[i].bottom && score <= this.severityRatings[i].top ) 
                return this.severityRatings[i].name
        }

        return undefined
    }
    
    calculateFromMetrics(metricValues) {
        const value = (key) => this.weight[key][metricValues[key]||"ND"]

        const impact = 10.41 * (1 - (1 - value('C')) * (1 - value("I")) * (1 - value('A')))
        const exploitability = this.exploitabilityCoefficient * value("AC") * value("Au") * value("AV")
        const baseScore = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * (impact === 0 ? 0 : 1.176)
        const temporalScore = baseScore * value("E") * value("RL") * value("RC")
        const modifiedImpact   = Math.min(10, 10.41 * (1 - (1 - value("C") * value("CR")) * (1 - value("I") * value("IR")) * (1 - value("A") * value("AR"))))
        const modifiedBase     = ((0.6 * modifiedImpact) + (0.4 * exploitability) - 1.5) * (modifiedImpact === 0 ? 0 : 1.176)
        const modifiedTemporal = modifiedBase * value("E") * value("RL") * value("RC")
        const envScore  = (modifiedTemporal + (10 - modifiedTemporal) * value("CDP")) * value("TD")

        const vectorString = this.baseKeys
            .concat( this.temporalKeys )
            .concat( this.environmentKeys )
            .map(key => `${key}:${metricValues[key]||"ND"}`)
            .join("/")
        
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
            metricValues,
            vectorString,
            version:this.version,
            adjust:(metrics={}) => this.calculateFromMetrics( Object.assign(metricValues, metrics) )
        }
    }

    calculateFromVector(vectorString) {
        if( !this.#vectorRegex.test(vectorString) ) 
            return this.error("Malformed V2 Vector String")

        const vectorMatches = vectorString.match(this.#vectorPattern)
        const metricValues = vectorMatches.reduce((acc,m) => {
            const [key, val] = m.split(':')
            if( key && val ) acc[key] = val
            return acc
        },{})
    
        return this.calculateFromMetrics(metricValues)
    }

    describe(vectorOrMetrics) {
        return typeof vectorOrMetrics === 'string'
            ? this.describeVector(vectorOrMetrics)
            : this.describeMetrics(vectorOrMetrics)
    }

    describeVector(vectorString) {
        if( typeof vectorString !== 'string' || !vectorString?.length ) 
            throw new Error('CVSS vector string required')

        if( !this.#vectorRegex.test(vectorString) ) 
            return this.error("Malformed V2 Vector String")

        const vectorMatches = vectorString.match(this.#vectorPattern)
        const metricValues = vectorMatches.reduce((acc,m) => {
            const [key, val] = m.split(':')
            if( key && val ) acc[key] = val
            return acc
        },{})
    
        return this.describeMetrics(metricValues)
    }

    describeMetrics(metricValues) {
        if( typeof metricValues !== 'object' ) 
            throw new Error('Metrics object required')

        return this.metricKeys.reduce((acc,key) => {
            acc[this.metricNames[key]] = this.metricValues[key][metricValues[key]]
            return acc
        },{})
    
    }
}

class CVSS3 {
    #vectorRegex = /CVSS:3(\.\d){0,1}\/((AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])\/)*(AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])/

    constructor(options={}) {
        this.version = options.version || "CVSS:3.1"
        this.exploitabilityCoefficient = options.exploitabilityCoefficient || 8.22
        this.scopeCoefficient = options.scopeCoefficient || 1.08
        this.weight = options.weight || {
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
        this.severityRatings = options.severityRatings || [
            { name: "None", bottom: 0.0, top: 0.0 }, 
            { name: "Low", bottom: 0.1, top: 3.9 }, 
            { name: "Medium", bottom: 4.0, top: 6.9 }, 
            { name: "High", bottom: 7.0, top: 8.9 }, 
            { name: "Critical", bottom: 9.0, top: 10.0 }
        ]
        this.metricKeys = ['AV','AC','PR','UI','S','C','I','A','E','RL','RC','CR','IR','AR','MAV','MAC','MPR','MUI','MS','MC','MI','MA']
        this.metricNames = {
            AV:  'Attack Vector',
            AC:  'Attack Complexity',
            PR:  'Privileges Required',
            UI:  'User Interaction',
            S:   'Scope',
            C:   'Confidentiality',
            I:   'Integrity',
            A:   'Availability',
            E:   'Exploit Code Maturity',
            RL:  'Remediation Level',
            RC:  'Report Confidence',
            CR:  'Confidentiality Requirement',
            IR:  'Integrity Requirement',
            AR:  'Availability Requirement',
            MAV: 'Modified Attack Vector',
            MAC: 'Modified Attack Complexity',
            MPR: 'Modified Privileges Required',
            MUI: 'Modified User Interaction',
            MS:  'Modified Scope',
            MC:  'Modified Confidentiality',
            MI:  'Modified Integrity',
            MA:  'Modified Availability'
        }
        this.metricValues = {
            E:    { X: "NOT_DEFINED", U: "UNPROVEN", P: "PROOF_OF_CONCEPT", F: "FUNCTIONAL", H: "HIGH" },
            RL:   { X: "NOT_DEFINED", O: "OFFICIAL_FIX", T: "TEMPORARY_FIX", W: "WORKAROUND", U: "UNAVAILABLE" },
            RC:   { X: "NOT_DEFINED", U: "UNKNOWN", R: "REASONABLE", C: "CONFIRMED" },
            CIAR: { X: "NOT_DEFINED", L: "LOW", M: "MEDIUM", H: "HIGH" },
            MAV:  { X: "NOT_DEFINED", N: "NETWORK", A: "ADJACENT_NETWORK", L: "LOCAL", P: "PHYSICAL" },
            MAC:  { X: "NOT_DEFINED", H: "HIGH", L: "LOW" },
            MPR:  { X: "NOT_DEFINED", N: "NONE", L: "LOW", H: "HIGH" },
            MUI:  { X: "NOT_DEFINED", N: "NONE", R: "REQUIRED" },
            MS:   { X: "NOT_DEFINED", U: "UNCHANGED", C: "CHANGED" },
            MCIA: { X: "NOT_DEFINED", N: "NONE", L: "LOW", H: "HIGH" },
            /*duplicates*/
            C:    { X: "NOT_DEFINED", L: "LOW", M: "MEDIUM", H: "HIGH" },
            R:    { X: "NOT_DEFINED", L: "LOW", M: "MEDIUM", H: "HIGH" },
            CR:   { X: "NOT_DEFINED", L: "LOW", M: "MEDIUM", H: "HIGH" },
            IR:   { X: "NOT_DEFINED", L: "LOW", M: "MEDIUM", H: "HIGH" },
            AR:   { X: "NOT_DEFINED", L: "LOW", M: "MEDIUM", H: "HIGH" },
            AV:   { N: "NETWORK", A: "ADJACENT_NETWORK", L: "LOCAL", P: "PHYSICAL" },
            AC:   { H: "HIGH", L: "LOW" },
            PR:   { N: "NONE", L: "LOW", H: "HIGH" },
            UI:   { N: "NONE", R: "REQUIRED" },
            S:    { U: "UNCHANGED", C: "CHANGED" },
            I:    { L: "LOW", M: "MEDIUM", H: "HIGH" },
            A:    { L: "LOW", M: "MEDIUM", H: "HIGH" },
            MC:   { X: "NOT_DEFINED", N: "NONE", L: "LOW", H: "HIGH" },
            MI:   { X: "NOT_DEFINED", N: "NONE", L: "LOW", H: "HIGH" },
            MA:   { X: "NOT_DEFINED", N: "NONE", L: "LOW", H: "HIGH" },
        }        

    }

    error(reason, version = this.version) {
        return {
            baseMetricScore: 0,
            baseSeverity: null,
            baseImpact: 0,
            baseExploitability: 0,
            temporalMetricScore: 0,
            temporalSeverity: null,
            environmentalMetricScore: 0,
            environmentalSeverity: null,
            environmentalModifiedImpact: 0,
            vectorValues:{},
            vectorString:reason,
            version
        }
    }

    roundUp(input) {
        const int_input = Math.round(input * 100000)
        return int_input % 10000 === 0
            ? int_input / 100000
            : (Math.floor(int_input / 10000) + 1) / 10
    }
    
    severityRating(score) {
        const severityRatingLength = this.severityRatings.length
        const validatedScore = Number(score)
        if( isNaN(validatedScore) ) 
            return validatedScore

        for( let i = 0; i < severityRatingLength; i++ ) {
            if( score >= this.severityRatings[i].bottom && score <= this.severityRatings[i].top ) 
                return this.severityRatings[i].name
        }

        return undefined
    }

    calculateFromMetrics(metricValues, version = this.version) {
        const { 
            AV = null, AC = null, PR = null, UI = null, S = null, C = null, I = null, A = null, 
            E = 'X', RL = 'X', RC = 'X', CR = 'X',IR = 'X', AR = 'X', 
            MAV = 'X', MAC = 'X', MPR = 'X', MUI = 'X',MS = 'X', MC = 'X', MI = 'X', MA = 'X' 
        } = metricValues
        
        if( !AV || !AC || !PR || !UI || !S || !C || !I || !A ) 
            return this.error("Malformed V3.x Metrics")

        const metricWeightAV  = this.weight.AV[AV]
        const metricWeightAC  = this.weight.AC[AC]
        const metricWeightPR  = this.weight.PR[S][PR]
        const metricWeightUI  = this.weight.UI[UI]
        const metricWeightS   = this.weight.S[S]
        const metricWeightC   = this.weight.CIA[C]
        const metricWeightI   = this.weight.CIA[I]
        const metricWeightA   = this.weight.CIA[A]
        const metricWeightE   = this.weight.E[E]
        const metricWeightRL  = this.weight.RL[RL]
        const metricWeightRC  = this.weight.RC[RC]
        const metricWeightCR  = this.weight.CIAR[CR]
        const metricWeightIR  = this.weight.CIAR[IR]
        const metricWeightAR  = this.weight.CIAR[AR]
        const metricWeightMAV = this.weight.AV[MAV !== "X" ? MAV : AV]
        const metricWeightMAC = this.weight.AC[MAC !== "X" ? MAC : AC]
        const metricWeightMPR = this.weight.PR[MS !== "X" ? MS : S][MPR !== "X" ? MPR : PR]
        const metricWeightMUI = this.weight.UI[MUI !== "X" ? MUI : UI]
        const metricWeightMS  = this.weight.S[MS !== "X" ? MS : S]
        const metricWeightMC  = this.weight.CIA[MC !== "X" ? MC : C]
        const metricWeightMI  = this.weight.CIA[MI !== "X" ? MI : I]
        const metricWeightMA  = this.weight.CIA[MA !== "X" ? MA : A]

        const iss = (1 - ((1 - metricWeightC) * (1 - metricWeightI) * (1 - metricWeightA)))
        const impact = S === 'U' 
            ? metricWeightS * iss
            : metricWeightS * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)

        const exploitability = this.exploitabilityCoefficient * metricWeightAV * metricWeightAC * metricWeightPR * metricWeightUI
        const baseScore = impact <= 0 ? 0 : S === 'U'
            ? this.roundUp(Math.min((exploitability + impact), 10))
            : this.roundUp(Math.min(this.scopeCoefficient * (exploitability + impact), 10))

        const temporalScore = this.roundUp(baseScore * metricWeightE * metricWeightRL * metricWeightRC)
        const miss = Math.min(1 - ((1 - metricWeightMC * metricWeightCR) * (1 - metricWeightMI * metricWeightIR) * (1 - metricWeightMA * metricWeightAR)), 0.915)
        const modifiedImpact = MS === "U" || (MS === "X" && S === "U")
            ? metricWeightMS * miss
            : metricWeightMS * (miss - 0.029) - 3.25 * Math.pow(miss * 0.9731 - 0.02, 13)

        const modifiedExploitability = this.exploitabilityCoefficient * metricWeightMAV * metricWeightMAC * metricWeightMPR * metricWeightMUI
        const envScore = modifiedImpact <= 0 ? 0 : MS === "U" || (MS === "X" && S === "U") 
            ? this.roundUp(this.roundUp(Math.min((modifiedImpact + modifiedExploitability), 10)) * metricWeightE * metricWeightRL * metricWeightRC)
            : this.roundUp(this.roundUp(Math.min(this.scopeCoefficient * (modifiedImpact + modifiedExploitability), 10)) * metricWeightE * metricWeightRL * metricWeightRC)
        
        const vectorString = version + "/AV:" + AV + "/AC:" + AC + "/PR:" + PR + "/UI:" + UI + "/S:" + S + "/C:" + C + "/I:" + I + "/A:" + A + "/E:" + E + "/RL:" + RL + "/RC:" + RC + "/CR:" + CR + "/IR:" + IR + "/AR:" + AR + "/MAV:" + MAV + "/MAC:" + MAC + "/MPR:" + MPR + "/MUI:" + MUI + "/MS:" + MS + "/MC:" + MC + "/MI:" + MI + "/MA:" + MA

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
            metricValues,
            vectorString,
            version,
            adjust:(metrics={}) => this.calculateFromMetrics( Object.assign(metricValues, metrics), version )
        }
    }

    calculateFromVector(vectorString) {
        if( !this.#vectorRegex.test(vectorString) ) 
            return this.error("Malformed V3.x Vector String")

        const version = vectorString.match(/CVSS:3(\.\d){0,1}/)[0]
        const metricNameValue = vectorString.substring(version.length).split("/").slice(1)
        const metricValues = {}

        for( const i in metricNameValue ) {
            if( !metricNameValue.hasOwnProperty(i) ) continue
            const singleMetric = metricNameValue[i].split(":")
            metricValues[singleMetric[0]] = singleMetric[1]
        }

        return this.calculateFromMetrics(metricValues, version)
    }

    describe(vectorOrMetrics) {
        return typeof vectorOrMetrics === 'string'
            ? this.describeVector(vectorOrMetrics)
            : this.describeMetrics(vectorOrMetrics)
    }

    describeVector(vectorString) {
        if( typeof vectorString !== 'string' || !vectorString?.length ) 
            throw new Error('CVSS vector string required')

        if( !this.#vectorRegex.test(vectorString) ) 
            return this.error("Malformed V3.x Vector String")

        const version = vectorString.match(/CVSS:3(\.\d){0,1}/)[0]
        const metricNameValue = vectorString.substring(version.length).split("/").slice(1)
        const metricValues = {}

        for( const i in metricNameValue ) {
            if( !metricNameValue.hasOwnProperty(i) ) continue
            const singleMetric = metricNameValue[i].split(":")
            metricValues[singleMetric[0]] = singleMetric[1]
        }
    
        return this.describeMetrics(metricValues, version)
    }

    describeMetrics(metricValues, version = this.version) {
        if( typeof metricValues !== 'object' ) 
            throw new Error('Metrics object required')

        if( !metricValues.AV || !metricValues.AC || !metricValues.PR || !metricValues.UI || !metricValues.S || !metricValues.C || !metricValues.I || !metricValues.A ) 
            return this.error("Malformed V3.x Metrics")

        return this.metricKeys.reduce((acc,key) => {
            acc[this.metricNames[key]] = this.metricValues[key][metricValues[key]]
            return acc
        },{})
    }
}

class CVSS {
    constructor() {
        this.v2 = new CVSS2()
        this.v3 = new CVSS3()
    }

    calculate(vectorOrMetrics) {
        vectorOrMetrics = vectorOrMetrics || ''
        return typeof vectorOrMetrics === 'string'
            ? this.calculateFromVector(vectorOrMetrics)
            : this.calculateFromMetrics(vectorOrMetrics)
    }
    calculateFromVector(vectorString = '') {
        return !vectorString?.startsWith?.('CVSS:3') || vectorString?.match?.(/Au:[MSN]/) 
            ? this.v2.calculateFromVector(vectorString)
            : this.v3.calculateFromVector(vectorString)
    }
    calculateFromMetrics(metricValues = {}) {
        return metricValues?.hasOwnProperty?.("Au")
            ? this.v2.calculateFromMetrics(metricValues)
            : this.v3.calculateFromMetrics(metricValues)
    }

    describe(vectorOrMetrics) {
        vectorOrMetrics = vectorOrMetrics || ''
        return typeof vectorOrMetrics === 'string'
            ? this.describeVector(vectorOrMetrics)
            : this.describeMetrics(vectorOrMetrics)
    }
    describeVector(vectorString = '') {
        return !vectorString?.startsWith?.('CVSS:3') || vectorString?.match?.(/Au:[MSN]/)
            ? this.v2.describeVector(vectorString)
            : this.v3.describeVector(vectorString)
    }
    describeMetrics(metricValues = {}) {
        return metricValues?.hasOwnProperty?.("Au")
            ? this.v2.describeMetrics(metricValues)
            : this.v3.describeMetrics(metricValues)
    }
}

module.exports = CVSS
