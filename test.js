(async () => {
    const CVEAggregate = require('.')
    const cves = new CVEAggregate(process.argv[2], true)
    const cveList = ['CVE-2023-35390','CVE-2023-35391','CVE-2023-38180']

    console.log('-'.repeat(30))
    await cves.build()

    // console.log('-'.repeat(30))
    // await cves.update()        

    // console.log('-'.repeat(30))
    // cves.report()

    // console.log('-'.repeat(30))
    // console.log('CVEs', 'queued', cveList)
    // console.log('CISA', 'in-KEV', cves.getCISA(...cveList)) //Is at least one of these CVEs in the KEV?
    // console.log('EPSS', 'scaled', cves.getEPSS(...cveList)) //Scaled product of all EPSS
    // console.log('CVSS', 'scored', cves.getCVSS(...cveList)) //Maximum score of all CVSS

    // console.log('-'.repeat(30))
    // console.log('CISA', cves.mapCISA(...cveList))
    // console.log('EPSS', cves.mapEPSS(...cveList))
    // console.log('CVSS', cves.mapCVSS(...cveList))

    // console.log('-'.repeat(30))
    // let v2score = cves.calculateCVSS("AV:N/AC:L/Au:N/C:C/I:C/A:C")
    // let v2adjusted = v2score.adjust({ E:"F", RL:"U" })
    // //console.log({v2score, v2adjusted})
    // console.log(cves.describeCVSS(v2adjusted.vectorString))
    
    // console.log('-'.repeat(30))
    // let v3score = cves.calculateCVSS("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H")
    // let v3adjusted = v3score.adjust({ E:"F", CR:"H" })
    // console.log({v3score, v3adjusted})
    // console.log(cves.describeCVSS(v3adjusted.vectorString))

    console.log('-'.repeat(30))
    console.log(cves.search({ 
        epss:{ gt:0.7 }, 
        cvss:{ gt:9.0 },
        cisa:{ gte:'2023-09-01' }
    }))

})()