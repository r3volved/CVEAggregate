import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))

const testCVEAggregate = async (...tests) => {
    const cveLibPath = join(__dirname, '..', 'src', 'index.js')
    const { CVEAggregate } = await import(cveLibPath)

    const verbose = true
    const filepath = join(__dirname, 'test_cves.json')
    const cves = new CVEAggregate(filepath, verbose)
    const cveList = ['CVE-2023-35390','CVE-2023-35391','CVE-2023-38180']

    const testers = {
        build:async () => {
            cves.log('- Testing buld without save -')
            await cves.build(false)
        },
        update:async () => {
            cves.log('- Testing update with save - ')
            await cves.update(true)
        },
        report:async () => {
            cves.log('-'.repeat(30))
            cves.report()
        },
        gets:async () => {
            cves.log('-'.repeat(30))
            cves.log('CVEs', 'queued', cveList)
            cves.log('CISA', 'in-KEV', cves.getCISA(...cveList)) //Is at least one of these CVEs in the KEV?
            cves.log('EPSS', 'scaled', cves.getEPSS(...cveList)) //Scaled product of all EPSS
            cves.log('CVSS', 'scored', cves.getCVSS(...cveList)) //Maximum score of all CVSS
            cves.log('-'.repeat(30))
            cves.log('FULL', cves.list(...cveList))
        },
        maps:async () => {
            cves.log('-'.repeat(30))
            cves.log('CVEs', 'queued', cveList)
            cves.log('CISA', cves.mapCISA(...cveList))
            cves.log('EPSS', cves.mapEPSS(...cveList))
            cves.log('CVSS', cves.mapCVSS(...cveList))
            cves.log('-'.repeat(30))
            cves.log('FULL', cves.map(...cveList))
        },
        cvss:async () => {
            cves.log('-'.repeat(30))
            let v2vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C"
            cves.log('Vector', v2vector)
            let v2score = cves.calculateCVSS(v2vector)
            cves.log('Score', v2score)
            let v2adjusted = v2score.adjust({ E:"F", RL:"U" })
            cves.log('Adjusted', v2adjusted)
            cves.log('Description', cves.describeCVSS(v2adjusted.vectorString))

            cves.log('-'.repeat(30))
            let v3vector = "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
            cves.log('Vector', v3vector)
            let v3score = cves.calculateCVSS(v3vector)
            cves.log('Score', v3score)
            let v3adjusted = v3score.adjust({ E:"F", CR:"H" })
            cves.log('Adjusted', v3adjusted)
            cves.log('Description', cves.describeCVSS(v3adjusted.vectorString))
        },
        search:async () => {
            cves.log('-'.repeat(30))
            cves.log('Search', cves.search({ 
                epss:{ gt:0.7 }, 
                cvss:{ gt:9.0 },
                cisa:{ gte:'2023-09-01' }
                // cisa:{ ne:null }
            }))
        },
        check:async () => {
            cves.log('-'.repeat(30))
            cves.log(cves.check(...cveList))        
        },
        chart:async () => {
            cves.log('-'.repeat(30))

            const aggregate = cves.cveList().map(id => {
                const check = cves.check(id)
                return { id, ...check }
            })

            const s_lim = [ 10, 1 ]//.map(v => v * 2)
            const p_lim = [ 10, 1 ].map(v => v * 2)

            process.stdout.write(' ')
            for(let p = 0; p <= p_lim[0]; ++p) {
                process.stdout.write(p==p_lim[0] ? '*' : !(p % p_lim[1]) ? (p/p_lim[1]).toString() : '\u252C')
            }
            process.stdout.write('\n')

            for(let s = s_lim[0]; s >= 0; --s) {
                process.stdout.write(s==s_lim[0] ? '*' : !(s % s_lim[1]) ? (s/s_lim[1]).toString() : '\u251C')
                const severity = aggregate.filter(a => Math.floor(a.peak.cvss * s_lim[1]) == s)
                // process.stdout.write(`${severity.length}: ${severity[0]}`)
                for(let p = 0; p <= p_lim[0]; ++p) {
                    const probability = severity.filter(a => Math.floor(a.peak.epss * p_lim[0]) == p)
                    let color = !probability.length ? 40    //black
                        : probability.length < 5 ? 47       //white
                        : probability.length < 10 ? 42      //green
                        : probability.length < 25 ? 46      //cyan
                        : probability.length < 100 ? 44     //blue
                        : probability.length < 500 ? 43     //yellow
                        : 41                                //red
                    // process.stdout.write(`${probability.length} `)
                    // let pct = Math.round(probability.length / (severity.length||1))
                    // const color = `48;2;${pct};${pct};${pct}`
                    // process.stdout.write(`\x1b[${color}m${pct} \x1b[49m`)
                    // process.stdout.write(`\x1b[${color}m \x1b[49m`)
                    process.stdout.write(`\x1b[${color}m \x1b[49m`)
                }
                process.stdout.write(s==s_lim[0] ? '*' : !(s % s_lim[1]) ? (s/s_lim[1]).toString() : '\u2524')
                process.stdout.write('\n')
                // break
            }

            process.stdout.write(' ')
            for(let p = 0; p <= p_lim[0]; ++p) {
                process.stdout.write(p==p_lim[0] ? '*' : !(p % p_lim[1]) ? (p/p_lim[1]).toString() : '\u2534')
            }
            process.stdout.write('\n')

        }
    }

    //If no tests specified, test all
    if( !tests.length ) 
        tests = Object.keys(testers)

    cves.log('-'.repeat(30))
    cves.log('TESTING CVEAggregate')
    for(const test of tests) {
        await testers?.[test]?.()
    }    
}

testCVEAggregate(
    // 'build', 'report',
    'update', 'report',
    'gets',
    'maps',
    'cvss',
    'search',
    'check',
    'chart'
)

