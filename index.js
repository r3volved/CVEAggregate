const { writeFileSync, readFileSync, existsSync } = require('fs')

const path = require('path')

const CVSS = require(path.join(__dirname, 'cvss.js'))

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
    #CVSS    = new CVSS()

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
            const score = this.#CVSS.calculateFromVector(this.cves[cveId]?.cvss3 || this.cves[cveId]?.cvss2)
            return Math.max(max, score.environmentalMetricScore)
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



    //Calculate a CVSS scoring from a vector string 
    calculateCVSS(vectorString) {
        return this.#CVSS.calculate(vectorString)
    }

    //Describe a CVSS vector or metrics object
    describeCVSS(vectorOrMetrics) {
        return this.#CVSS.describe(vectorOrMetrics)
    }

    
}

module.exports = CVEAggregate

