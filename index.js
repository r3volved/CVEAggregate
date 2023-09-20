import { writeFileSync, readFileSync, existsSync } from 'fs'
import { fileURLToPath } from 'url'
import { join, dirname } from 'path'

const __dirname = dirname(fileURLToPath(import.meta.url))
const cvssLibPath = join(__dirname, 'cvss.js')
const { CVSS } = await import(cvssLibPath)

/**
 * Get the difference between two dates (in days)
 * @param  {Date}   date1    
 * @param  {Date}   date2   Optional second date to use instead of current date
 * @return {number} Difference in days (floating point)
 */
const diffInDays = (date1, date2 = Date.now()) => {
    const last = new Date(date1)
    const now  = new Date(date2)
    const Difference_In_Time = now.getTime() - last.getTime()
    const Difference_In_Days = Difference_In_Time / (1000 * 3600 * 24)
    return Difference_In_Days
}

/**
 * Compare a value against a condition (optional format func)
 * @param  {*}      val     The value from the aggregate
 * @param  {object} option  The condition to compare with
 * @param  {func}   format  Optional formatting function for normalizing both sides of the condition
 * @return {bool}   Whether the value matches the condition
 */
const compare = (val, option, format) => {
    const key = Object.keys(option||{})[0]
    return !key ? false : typeof format === 'function'
        ? compareFunc[key]( val === null ? val : format(val), format(option[key]) )
        : compareFunc[key]( val, option[key] )
}

/** 
 * Comparison functions mapped by key (gt,gte,lt,lte,eq,ne,neq)
 */
const compareFunc = {
    gt: (v1, v2) => v1 > v2,    //Greater than
    gte:(v1, v2) => v1 >= v2,   //Greater than, or equal
    lt: (v1, v2) => v1 < v2,    //Less than
    lte:(v1, v2) => v1 <= v2,   //Less than, or equal
    eq: (v1, v2) => v1 === v2,  //Is equal
    ne: (v1, v2) => v1 !== v2,  //Not equal
    neq:(v1, v2) => v1 !== v2,  //Same as ne
}

export class Logger {
    constructor() {
        this.logging = false
    }

    /**
     * Log to console
     * @param {Error}   lines an error object to throw in console
     */
    error(err) {
        this.logging = false
        console.error(lines)
    }

    /**
     * Log multiple lines console
     * @param {array}   lines a list of strings to replace the last n-lines in console if the last log was array
     */
    multi(lines) {
        if( this.logging ) {
            process.stdout.moveCursor(0, -1*(lines.length))
            process.stdout.clearLine(0)
            process.stdout.cursorTo(0)
        }
        process.stdout.write(lines.join('\n')+'\n')
        this.logging = true
    }

    /**
     * Log to console
     * @param {array}   lines a list of strings to replace the last n-lines in console if the last log was array
     * @param {Error}   lines an error object to throw in console
     * @param {any}     lines any other value/type to log in console
     */
    log(lines) {
        if( lines === undefined ) return
        if( lines instanceof Error ) return this.error(lines)
        if( Array.isArray(lines) ) return this.multi(lines)

        this.logging = false
        console.log(lines)        
    }    
}

export class CVEAggregate { 
    #urlCVES = "https://cve.mitre.org/data/downloads/allitems.csv"
    #urlCISA = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    #urlEPSS = "https://api.first.org/data/v1/epss"
    #urlCVSS = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    #CVSS    = new CVSS()
    #weight = { cisa:0.8, epss:0.8, cvss:0.5 }

    constructor(filepath, verbose = false){
        this.filepath    = filepath?.length ? filepath : null //join(__dirname, 'cves.json')
        this.verbose     = verbose
        this.logger      = verbose ? new Logger() : { log:() => {} }
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

    /**
     * Log to console
     * @param {array}   lines a list of strings to replace the last n-lines in console if the last log was array
     * @param {Error}   lines an error object to throw in console
     * @param {any}     lines any other value/type to log in console
     */
    log(lines) {
        this.logger.log(lines)
    }

    /**
     * Dump internal details
     * @return {object} contents of the current cve json
     */
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

    /**
     * Save current cves to filepath
     */
    save(filepath = this.filepath) {
        this.lastUpdated = (new Date()).toISOString()
        if( filepath?.length ) 
            writeFileSync(filepath, JSON.stringify(this.dump()), 'utf8')
    }

    /**
     * Load cves from a filepath
     */
    load(filepath = this.filepath) {
        try { 
            if( !existsSync(filepath) ) throw new Error('No cve list')
            //Load the content of last save
            const json = JSON.parse(readFileSync(filepath, 'utf8')) 
            this.cves        = json.cves        || this.cves
            this.lastUpdated = json.lastUpdated || this.lastUpdated
            this.lastCount   = json.lastCount   || this.lastCount
            this.cvesUpdated = json.cvesUpdated || this.cvesUpdated
            this.cisaUpdated = json.cisaUpdated || this.cisaUpdated
            this.epssUpdated = json.epssUpdated || this.epssUpdated
            this.cvssUpdated = json.cvssUpdated || this.cvssUpdated
        } catch(e) { 
            //No file or error loading, create fresh
            this.cves        = this.cves        || {}   
            this.lastUpdated = this.lastUpdated || null 
            this.lastCount   = this.lastCount   || null 
            this.cvesUpdated = this.cvesUpdated || null 
            this.cisaUpdated = this.cisaUpdated || null 
            this.epssUpdated = this.epssUpdated || null 
            this.cvssUpdated = this.cvssUpdated || null 
        }
        this.reset()
    }

    reset() {
        //reset the new item counters
        this.newCVES  = new Set()
        this.newCISA  = new Set()
        this.newEPSS  = new Set()
        this.newCVSS2 = new Set()
        this.newCVSS3 = new Set()
    }

    /**
     * Report update details since last load
     * @return {object} collection of data details
     */
    report(reportZero) {
        if( reportZero || this.newCVES.size )  this.logger.log(`Found ${this.newCVES.size.toLocaleString()} new CVEs`)
        if( reportZero || this.newCISA.size )  this.logger.log(`Found ${this.newCISA.size.toLocaleString()} new CISA entries`)
        if( reportZero || this.newEPSS.size )  this.logger.log(`Found ${this.newEPSS.size.toLocaleString()} new EPSS scores`)
        if( reportZero || this.newCVSS2.size ) this.logger.log(`Found ${this.newCVSS2.size.toLocaleString()} new CVSSv2 vectors`)
        if( reportZero || this.newCVSS3.size ) this.logger.log(`Found ${this.newCVSS3.size.toLocaleString()} new CVSSv3 vectors`)
        //If anything found, add a divider line
        if( reportZero || this.newCVES.size || this.newCISA.size || this.newEPSS.size || this.newCVSS2.size || this.newCVSS3.size )
            this.logger.log(`-`.repeat(30))

        //Collect and return details in one object
        const data = this.dump()

        data.newCVES   = this.newCVES
        data.newCISA   = this.newCISA
        data.newEPSS   = this.newEPSS
        data.newCVSS2  = this.newCVSS2
        data.newCVSS3  = this.newCVSS3
        data.totalCVES = Object.keys(this.cves).length
        data.totalCISA = Object.values(this.cves).filter(i => i.cisa).length
        data.totalEPSS = Object.values(this.cves).filter(i => i.epss).length
        data.totalCVSS = Object.values(this.cves).filter(i => i.cvss2 || i.cvss3).length

        this.logger.log(`Total CVEs:         ${data.totalCVES.toLocaleString()}`)
        this.logger.log(`Total CISA entries: ${data.totalCISA.toLocaleString()}`)
        this.logger.log(`Total EPSS scores:  ${data.totalEPSS.toLocaleString()}`)
        this.logger.log(`Total CVSS vectors: ${data.totalCVSS.toLocaleString()}`)
        
        return data
    }

    /* ACCESSORS */

    /**
     * Search one or more CVEs to see if they're in the CISA KEV
     * @param {...string} cveIds    CVE ids to search against
     * @return {bool} true if any cve is in CISA
     */
    getCISA(...cveIds) {
        for(const cveId of cveIds) {
            if( this.cves[cveId]?.cisa?.length ) return true
        }
        return false
    }

    /**
     * Get the scaled EPSS score of one or more CVEs
     * @param {...string} cveIds    CVE ids to search against
     * @return {number} EPSS score
     */
    getEPSS(...cveIds) {
        return (1 - cveIds.map(cveId => this.cves[cveId]?.epss || 0).filter(v => v).reduce((p,v) => p * (1-v),1))
    }

    /**
     * Get the maximum CVSS score of one or more CVEs
     * @param {...string} cveIds    CVE ids to search against
     * @return {number} CVSS score
     */
    getCVSS(...cveIds) {
        return cveIds.reduce((max,cveId) => {
            const score = this.#CVSS.calculateFromVector(this.cves[cveId]?.cvss3 || this.cves[cveId]?.cvss2)
            return Math.max(max, score.environmentalMetricScore)
        },0)
    }

    /* MAPPERS */

    /**
     * Map the CISA due dates to one or more CVEs
     * @param {...string} cveIds    CVE ids to search against
     * @return {object} due dates keyed by CVE id
     */
    mapCISA(...cveIds) { 
        return cveIds.reduce((map,cveId) => {
            map[cveId] = this.cves[cveId]?.cisa || null
            return map
        },{})
    }
    
    /**
     * Map the EPSS score to one or more CVEs
     * @param {...string} cveIds    CVE ids to search against
     * @return {object} EPSS scores keyed by CVE id
     */
    mapEPSS(...cveIds) { 
        return cveIds.reduce((map,cveId) => {
            map[cveId] = this.cves[cveId]?.epss || 0
            return map
        },{})
    }

    /**
     * Map the CVSS score to one or more CVEs (v3 if exists, else v2)
     * @param {...string} cveIds    CVE ids to search against
     * @return {object} CVSS scores keyed by CVE id
     */
    mapCVSS(...cveIds) { 
        return cveIds.reduce((map,cveId) => {
            map[cveId] = this.cves[cveId]?.cvss3 || this.cves[cveId]?.cvss2 || null
            return map
        },{})
    }

    /* PARSERS */

    /**
     * Parse a line from the CVE-CSV - looking for CVE ids
     * @param {string} line     one record from the CVE.csv
     */
    parseCSVLine(line) {
        if( !line.length ) return
        
        const cveId = line?.match?.(/^(CVE-\d{4}-\d{4,})\s*,/)?.[1]
        if( !cveId?.length ) return
        if( !(cveId in this.cves) ) {
            this.cves[cveId] = { days:0, cisa:null, epss:0, cvss2:null, cvss3:null }
            this.newCVES.add(cveId)
        }
    }

    /**
     * Parse the due date from CISA entry
     * @param {object} item     Entry from the CISA KEV
     */
    parseCISA(item) {
        const cveId = item?.cveID
        if( !cveId?.length ) return
        if( !(cveId in this.cves) ) {
            this.cves[cveId] = { days:0, cisa:null, epss:0, cvss2:null, cvss3:null }
            this.newCVES.add(cveId)
        }

        if( this.cves[cveId].cisa === item.dueDate ) 
            return //Already the same

        if( !this.cves[cveId].cisa ) {
            this.newCISA.add(cveId)
        }
        this.cves[cveId].cisa = item.dueDate
        this.cves[cveId].days = diffInDays(item.dateAdded, item.dueDate)
    }
    
    /**
     * Parse the EPSS score from first.org response item
     * @param {object} item     Entry from the EPSS response
     */
    parseEPSS(item) {
        const cveId = item?.cve
        if( !cveId?.length ) return
        if( !(cveId in this.cves) ) {
            this.cves[cveId] = { days:0, cisa:null, epss:0, cvss2:null, cvss3:null }
            this.newCVES.add(cveId)
        }

        if( this.cves[cveId].epss === item.epss ) 
            return //Already the same

        if( !this.cves[cveId].epss ) {
            this.newEPSS.add(cveId)
        }
        this.cves[cveId].epss = Number(item.epss)
    }

    /**
     * Parse the CVSS scores from first.org response item
     * @param {object} item     Entry from the CVSS response
     */
    parseCVSS(item) {
        const cveId = item?.cve?.id
        if( !cveId?.length ) return
        if( !(cveId in this.cves) ) {
            this.cves[cveId] = { days:0, cisa:null, epss:0, cvss2:null, cvss3:null }
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

    /* UPDATE ROUTINES */

    /**
     * Stream the CVE-CSV from mitre.org and extract new entries
     * @param {array} feedback  array of console lines for updating feedback
     * @param {number} index    index of the feedback array for this function
     * @return {Promise}
     */
    async update_cves (feedback=[], index=0) {
        if( this.cvesUpdated?.length && diffInDays(this.cvesUpdated) < this.daysdiff ) 
            return feedback[index] = `Updating CVEs ... [skip]`

        const https = await import('node:https')
        const readline = await import('node:readline')
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
        .catch(e => this.logger.log(e))
        .finally(() => this.save())
    }

    /**
     * Fetch the CISA-KEV from cisa.gov and extract new entries
     * @param {array} feedback  array of console lines for updating feedback
     * @param {number} index    index of the feedback array for this function
     * @return {Promise}
     */
    async update_cisa (feedback=[], index=0) {
        if( this.cisaUpdated?.length && diffInDays(this.cisaUpdated) < this.daysdiff ) 
            return feedback[index] = `Updating CISA ... [skip]`

        return new Promise(async (resolve, reject) => {

            feedback[index] = `Updating CISA ... `
            const kev = await fetch(this.#urlCISA)
                .then(res => res.json())
                .catch(e => this.logger.log(e))
            
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
        .catch(e => this.logger.log(e))
        .finally(() => this.save())
    }
    
    /**
     * Fetch the EPSS scores from first.org and extract new entries
     * @param {array} feedback  array of console lines for updating feedback
     * @param {number} index    index of the feedback array for this function
     * @return {Promise}
     */
    async update_epss (feedback=[], index=0) {
        if( this.epssUpdated?.length && diffInDays(this.epssUpdated) < this.daysdiff ) 
            return feedback[index] = `Updating EPSS ... [skip]`
        
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
                .catch(e => this.logger.log(e))
    
            const { total = 1, data = [] } = firstBatch || {}
                
            let offset = data?.length || total || 1
            let pct = (offset / (total || 1) * 100).toFixed(1)
    
            feedback[index] = `Updating EPSS ... ${pct}%`
            data?.forEach?.(item => this.parseEPSS(item))
    
            let fails = 0
            while(total > offset) {
                const loopBatch = await fetch(`${this.#urlEPSS}?envelope=true&offset=${offset}${daysLimit}`)
                    .then(res => res.status < 400 ? res.json() : null)
                    .catch(e => this.logger.log(e))
    
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
        .catch(e => this.logger.log(e))
        .finally(() => this.save())
    }

    /**
     * Fetch the CVSS vectors from nist.gov and extract new entries
     * @param {array} feedback  array of console lines for updating feedback
     * @param {number} index    index of the feedback array for this function
     * @return {Promise}
     */
    async update_cvss (feedback=[], index=0) {
        if( this.cvssUpdated?.length && diffInDays(this.cvssUpdated) < this.daysdiff ) 
            return feedback[index] = `Updating CVSS ... [skip]`

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
                .catch(e => this.logger.log(e))

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
                    .catch(e => this.logger.log(e))
    
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
        .catch(e => this.logger.log(e))
        .finally(() => this.save())
    }
    
    /* Generate aggregate source */

    /**
     * Build with full CVE list
     * Includes the CVE csv where some CVEs will not have matching data
     * @return {Promise.<object>}
     */ 
    async build() {
        const feedback = new Array(4).fill('...')
        const interval = setInterval(() => this.logger.log(feedback), 1000)
        return Promise.all([
            this.update_cves(feedback, 0),
            this.update_cisa(feedback, 1),
            this.update_epss(feedback, 2),
            this.update_cvss(feedback, 3),
        ])
        .then(() => this.cves)
        .finally(() => {
            clearInterval(interval)
            this.logger.log(feedback)            
        })
    }

    /**
     * Build with only applicable CVEs
     * Only generate a list of CVEs that have data
     * @return {Promise.<object>}
     */
    async update() {
        const feedback = new Array(3).fill('...')
        const interval = setInterval(() => this.logger.log(feedback), 1000)
        return Promise.all([
            this.update_cisa(feedback, 0),
            this.update_epss(feedback, 1),
            this.update_cvss(feedback, 2),
        ])
        .then(() => this.cves)
        .finally(() => {
            clearInterval(interval)
            this.logger.log(feedback)
        })
    }


    /* Helper tools and calculators */

    /**
     * Calculate a CVSS scoring from a vector string 
     * @param {string} vectorOrMetrics  The CVSS (v2 or v3) vector string
     * @param {object} vectorOrMetrics  The CVSS metrics object
     * @return {object} calculation results
     */
    calculateCVSS(vectorOrMetrics) {
        return this.#CVSS.calculate(vectorOrMetrics)
    }

    /**
     * Describe a CVSS vector or metrics object
     * @param {string} vectorOrMetrics  The CVSS (v2 or v3) vector string
     * @param {object} vectorOrMetrics  The CVSS metrics object
     * @return {object} 
     */
    describeCVSS(vectorOrMetrics) {
        return this.#CVSS.describe(vectorOrMetrics)
    }

    /**
     * Search the aggregate with fields and conditions
     * ex. search({ epss:{ gt:0.5 } })
     * @param {object} options  condition objects keyed by data field
     * @return {object} full entries that match the given criteria
     */
    search(options={}) {
        const critical = {}
        for(const cveId in this.cves) {
            const { cisa, epss, cvss2, cvss3 } = this.cves[cveId]

            //First: Lightest compare
            const matchEPSS = !options?.epss || compare(epss, options?.epss, (v) => Number(v))
            if( !matchEPSS ) continue

            //Second: Date conversions
            const matchCISA = !options?.cisa || compare(cisa, options?.cisa, (v) => v ? new Date(v).getTime() : v)
            if( !matchCISA ) continue

            //Last: CVSS calculation
            const score = this.calculateCVSS(cvss3 || cvss2)
            const matchCVSS = !options?.cvss || compare(score.environmentalMetricScore, options?.cvss, (v) => Number(v))
            if( !matchCVSS ) continue

            const daysUntilDue = Math.round(diffInDays(Date.now(), cisa))

            //If here, we match, return the calculated cvss instead of any vectors
            critical[cveId] = { daysUntilDue, cisa, epss, cvss:score.environmentalMetricScore }
        }
        return critical
    }

    /**
     * Fetch entries from the aggregate for one or more CVEs
     * @param {...string} cveIds    CVE ids to search against
     * @return {object} full entries for the given CVEs
     */
    map(...cveIds) { 
        return cveIds.reduce((map,cveId) => {
            if( cveId in this.cves ) {
                map[cveId] = { ...this.cves[cveId] }
            }
            return map
        },{})
    }
    
    /**
     * Fetch entries from the aggregate for one or more CVEs
     * @param {...string} cveIds    CVE ids to search against
     * @return {array} full entries for the given CVEs
     */
    list(...cveIds) { 
        return cveIds.reduce((arr,cveId) => {
            if( cveId in this.cves ) {
                arr.push({ id:cveId, ...this.cves[cveId] })
            }
            return arr
        },[])
    }

    /**
     * Get list of all CVE Ids
     * @return {string[]} list of CVE ids
     */
    cveList() {
        return Object.keys(this.cves)
    }

    /**
     * Search one or more CVEs to check risk 
     * @param {...string} cveIds    CVE ids to search against
     * @return {object} risk
     */
    check(...cveIds) {
        const peak = { cisa:0, epss:0, cvss:0 }
        const list = { cisa:[], epss:[], cvss:[] }
        for(const cveId of cveIds) {
            const ref = this.cves[cveId]
            if( !ref ) continue
            if( ref.cisa ) {
                const days = Math.round(diffInDays(Date.now(), ref.cisa))
                if( days <= 0 ) list.cisa.push({date:ref.cisa, days, risk:100})
                else list.cisa.push({date:ref.cisa, days, risk:days / ref.days * 100})
            }
            if( ref.epss ) list.epss.push({score:ref.epss})
            if( ref.cvss3 || ref.cvss2 ) list.cvss.push({vector:ref.cvss3 || ref.cvss2})
        }

        peak.epss = (1 - list.epss.reduce((p,v) => p * (1-v.score),1))
        peak.cvss = list.cvss.reduce((max,{vector}) => {
            if( max === 10 ) return max
            const score = this.calculateCVSS(vector).environmentalMetricScore
            return Math.max(max, score)
        },0)

        peak.epss = { epss:peak.epss, risk:Math.round(peak.epss*100) }
        peak.cvss = { cvss:peak.cvss, risk:Math.round(peak.cvss*10) }
        peak.cisa = list.cisa.reduce((max,entry) => {
            if( entry.risk > max.risk ) return entry
            return max
        },{date:null,days:0,risk:0})
        
        let epss = peak.epss.risk * this.#weight.epss
        let cvss = peak.cvss.risk * this.#weight.cvss
        let cisa = peak.cisa.risk * this.#weight.cisa

        let num = epss + cvss + cisa
        let den = this.#weight.epss + this.#weight.cvss + this.#weight.cisa

        return { peak, risk:Math.round(num / (den || 1)) }
    }
    
}

