process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"

const express = require("express")
const axios = require("axios")

const app = express()
app.use(express.json())

const TEAMS_WEBHOOK = process.env.TEAMS_WEBHOOK
const HARBOR_URL = process.env.HARBOR_URL
const HARBOR_USER = process.env.HARBOR_USER
const HARBOR_PASSWORD = process.env.HARBOR_PASSWORD

async function sleep(ms){
  return new Promise(resolve => setTimeout(resolve, ms))
}

function buildRiskBar(critical, high, medium, low){

  const total = critical + high + medium + low
  if(total === 0) return "No vulnerabilities"

  const size = 20

  const c = Math.round((critical/total)*size)
  const h = Math.round((high/total)*size)
  const m = Math.round((medium/total)*size)
  const l = size - (c+h+m)

  return "🟥".repeat(c) + "🟧".repeat(h) + "🟨".repeat(m) + "🟩".repeat(l)
}

app.post("/harbor", async (req, res) => {

  try {

    const data = req.body

    const repo = data?.event_data?.repository?.repo_full_name
    const resource = data?.event_data?.resources?.[0]
    const digest = resource?.digest
    const tag = resource?.tag || "no-tag"

    if(!repo || !digest){
      return res.status(200).send("ignored")
    }

    const project = repo.split("/")[0]
    const repository = repo.split("/").slice(1).join("/")

    const artifactApi =
      `${HARBOR_URL}/api/v2.0/projects/${project}/repositories/${repository}/artifacts/${digest}`

    const artifactUI =
      `${HARBOR_URL}/harbor/projects/${project}/repositories/${repository}/artifacts/${digest}`

    let vulnPath = null
    let artifact = null

    for(let i=0;i<10;i++){

      const artifactResponse = await axios.get(
        artifactApi,
        {
          auth:{
            username:HARBOR_USER,
            password:HARBOR_PASSWORD
          }
        }
      )

      artifact = artifactResponse.data

      vulnPath = artifact?.addition_links?.vulnerabilities?.href

      if(vulnPath) break

      await sleep(3000)
    }

    if(!vulnPath){
      return res.status(200).send("no report")
    }

    const vulnUrl = `${HARBOR_URL}${vulnPath}`

    const vulnResponse = await axios.get(
      vulnUrl,
      {
        auth:{
          username:HARBOR_USER,
          password:HARBOR_PASSWORD
        }
      }
    )

    const report =
      vulnResponse.data[
        "application/vnd.security.vulnerability.report; version=1.1"
      ]

    let critical = 0
    let high = 0
    let medium = 0
    let low = 0

    const vulns = report?.vulnerabilities || []

    vulns.forEach(v => {

      switch(v.severity){
        case "Critical": critical++; break
        case "High": high++; break
        case "Medium": medium++; break
        case "Low": low++; break
      }

    })

    const total = critical + high + medium + low

    const topCVEs = vulns
      .sort((a,b)=>{
        const order = {Critical:4,High:3,Medium:2,Low:1}
        return order[b.severity]-order[a.severity]
      })
      .slice(0,5)
      .map(v => `• ${v.id} (${v.severity})`)
      .join("\n")

    const riskBar = buildRiskBar(critical,high,medium,low)

    const card = {
      type: "message",
      attachments: [
        {
          contentType: "application/vnd.microsoft.card.adaptive",
          content: {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            type: "AdaptiveCard",
            version: "1.4",
            body: [

              {
                type: "TextBlock",
                text: "Harbor Vulnerability Scan",
                weight: "Bolder",
                size: "Large"
              },

              {
                type: "FactSet",
                facts: [
                  {title:"Repository", value: repo},
                  {title:"Tag", value: tag},
                  {title:"Digest", value: digest.substring(0,20)+"..."}
                ]
              },

              {
                type: "TextBlock",
                text: "Risk Distribution",
                weight: "Bolder",
                spacing: "Medium"
              },

              {
                type: "TextBlock",
                text: riskBar,
                wrap: true
              },

              {
                type: "FactSet",
                facts: [
                  {title:"Critical", value:`${critical}`},
                  {title:"High", value:`${high}`},
                  {title:"Medium", value:`${medium}`},
                  {title:"Low", value:`${low}`},
                  {title:"Total", value:`${total}`}
                ]
              },

              {
                type: "TextBlock",
                text: "Top CVEs",
                weight: "Bolder",
                spacing: "Medium"
              },

              {
                type: "TextBlock",
                text: topCVEs || "None",
                wrap: true
              }

            ],

            actions: [
              {
                type: "Action.OpenUrl",
                title: "Open Artifact in Harbor",
                url: artifactUI
              }
            ]

          }
        }
      ]
    }

    await axios.post(TEAMS_WEBHOOK, card)

    res.status(200).send("notification sent")

  }
  catch(err){

    console.error(err.message)
    res.status(200).send("handled")

  }

})

app.listen(5000, ()=>{
  console.log("Harbor webhook adapter running on port 5000")
})
