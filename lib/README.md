# CVEAggregate
Build a CVE library with aggregated CISA, EPSS and CVSS data

- **CISA Values** : The remediation due date (or null)
- **EPSS Values** : The EPSS probability score (or 0)
- **CVSS Values** : V2 and/or V3 vector strings (or null)

```js
const { CVEAggregate } = require("/path/to/CVEAggregate/lib/index.cjs")

/* If verbose, will log stuff to console */
const verbose = true
const cves = new CVEAggregate('/path/to/cves.json', verbose)
```

## Building the aggregate

The path provided to the constructor will load file if exists and will save updates to same location.

The build process will collect all existing CVE Ids regardless of their state or age.

The update process will collect only the CVE Ids that have associated aggregate data (epps, cvss, cisa).

Note: *Once the initial aggregate has been created, subsequent build or update calls will only collect new items since last save.*

```js
/* Build full list */
await cves.build()

/* Build short list */
await cves.update()

/* List new items since last load, plus aggregate totals and details */
cves.report() 

/* Return the full json aggregate */
const data = cves.dump()     

/* Force save (to the filepath provided) */
cves.save()

/* Force load (from the filepath provided) */
cves.load()
```

## Accessing the aggregate

Helper functions are provided to help access and reference the aggregate

```js
const listOfCves = ['CVE-2023-35390','CVE-2023-35391','CVE-2023-38180']

/* Get matching cve entries as an object */
const map = cves.map(...listOfCves)
//> {
//>   'CVE-2023-35390': {
//>     days: 0,
//>     cisa: null,
//>     epss: 0.00564,
//>     cvss2: null,
//>     cvss3: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H'
//>   },
//>   'CVE-2023-35391': {
//>     days: 0,
//>     cisa: null,
//>     epss: 0.00114,
//>     cvss2: null,
//>     cvss3: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
//>   },
//>   'CVE-2023-38180': {
//>     days: 21,
//>     cisa: '2023-08-30',
//>     epss: 0.00484,
//>     cvss2: null,
//>     cvss3: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'
//>   }
//> }

/* Get matching cve entries as an array */
const list = cves.list(...listOfCves)
//> [
//>   {
//>     id: 'CVE-2023-35390',
//>     days: 0,
//>     cisa: null,
//>     epss: 0.00564,
//>     cvss2: null,
//>     cvss3: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H'
//>   },
//>   {
//>     id: 'CVE-2023-35391',
//>     days: 0,
//>     cisa: null,
//>     epss: 0.00114,
//>     cvss2: null,
//>     cvss3: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
//>   },
//>   {
//>     id: 'CVE-2023-38180',
//>     days: 21,
//>     cisa: '2023-08-30',
//>     epss: 0.00484,
//>     cvss2: null,
//>     cvss3: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'
//>   }
//> ]

/* Get the whole list of CVE IDs in the cache */
const allCVEs = cves.cveList()
```

Get a value reduced/scaled across one or more CVE Ids

```js
/* Check one or more CVE Ids if (any) in the CISA KEV */
const inKEV = cves.getCISA(...listOfCves)   
//> true

/* Get the scaled EPSS score for one or more CVE Ids */
const epssScore = cves.getEPSS(...listOfCves)    
//> 0.011580786319263958

/* Get the maximum CVSS score across one or more CVE Ids */
const cvssScore = cves.getCVSS(...listOfCves)
//> 7.8
```

Get the full mapping of CVE Ids -to- values

```js
const cisaMap = cves.mapCISA(...listOfCves) 
//> { 
//>   'CVE-2023-35390': null, 
//>   'CVE-2023-35391': null, 
//>   'CVE-2023-38180': '2023-08-30' 
//> }

const epssMap = cves.mapEPSS(...listOfCves)
//> { 
//>   'CVE-2023-35390': 0.00564, 
//>   'CVE-2023-35391': 0.00114, 
//>   'CVE-2023-38180': 0.00484 
//> }

const cvssMap = cves.mapCVSS(...listOfCves)
//> {
//>   'CVE-2023-35390': 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
//>   'CVE-2023-35391': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
//>   'CVE-2023-38180': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'
//> }
```

Search the aggregate with criteria (gt, gte, lt, lte, eq, ne)

```js
const critical = cves.search({ 
    epss:{ gt:0.7 }, 
    cvss:{ gt:9.0 },
    cisa:{ gte:'2023-09-01' }
})
//> {
//>   'CVE-2023-24489': { daysUntilDue: -14, cisa: '2023-09-06', epss: 0.97441, cvss: 9.8 },
//>   'CVE-2023-38035': { daysUntilDue: -8, cisa: '2023-09-12', epss: 0.96013, cvss: 9.8 },
//>   'CVE-2023-33246': { daysUntilDue: 7, cisa: '2023-09-27', epss: 0.97146, cvss: 9.8 },
//>   'CVE-2021-3129': { daysUntilDue: 19, cisa: '2023-10-09', epss: 0.97515, cvss: 9.8 }
//> }
```


## Calculations

The aggregate uses CVSS vectors and calculates the CVSS scores as needed

This allows the ability to manipulate vectors with optional temporal and environmental metrics 

```js
//Calculate a CVSSv2 vector details
const cvss2 = cves.calculateCVSS("AV:N/AC:L/Au:N/C:C/I:C/A:C")
//> {
//>   baseMetricScore: 7.2,
//>   baseSeverity: 'High',
//>   baseImpact: 10.00084536,
//>   baseExploitability: 4.1086848,
//>   temporalMetricScore: 7.2,
//>   temporalSeverity: 'High',
//>   environmentalMetricScore: 7.2,
//>   environmentalSeverity: 'High',
//>   environmentalModifiedImpact: 10,
//>   metricValues: { AV:'N', AC:'L', Au:'N', C:'C', I:'C', A:'C' },
//>   vectorString: 'AV:N/AC:L/Au:N/C:C/I:C/A:C/E:ND/RL:ND/RC:ND/CDP:ND/TD:ND/CR:ND/IR:ND/AR:ND',
//>   version: 'CVSS:2'
//> }

//Calculate a CVSSv3 vector details
const cvss3 = cves.calculateCVSS("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H")
//> {
//>   baseMetricScore: 7.8,
//>   baseSeverity: 'High',
//>   baseImpact: 5.873118720000001,
//>   baseExploitability: 1.8345765900000002,
//>   temporalMetricScore: 7.8,
//>   temporalSeverity: 'High',
//>   environmentalMetricScore: 7.8,
//>   environmentalSeverity: 'High',
//>   environmentalModifiedImpact: 5.873118720000001,
//>   metricValues: { AV:'L', AC:'L', PR:'N', UI:'R', S:'U', C:'H', I:'H', A:'H' },
//>   vectorString: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/E:X/RL:X/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X',
//>   version: 'CVSS:3.1'
//> }
```

## Aggregate structure

Example of the aggregated cves.json

```json
{
    "lastUpdated": "2023-08-31T14:41:33.076Z",
    "cvesUpdated": null,
    "cisaUpdated": "2023-08-31T14:35:31.532Z",
    "epssUpdated": "2023-08-31T14:41:33.076Z",
    "cvssUpdated": "2023-08-31T14:49:33.076Z",
    "lastCount": 216857,
    "cves": {
         "CVE-2018-4939": {
            "cisa": "2022-05-03",
            "epss": 0.97236,
            "cvss2": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
            "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        },
        "CVE-2018-4878": {
            "cisa": "2022-05-03",
            "epss": 0.9742,
            "cvss2": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        },
        ...
    }
}
```
