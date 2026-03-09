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

app.post("/harbor", async (req, res) => {

  try {

    const data = req.body

    console.log("Webhook received")

    const repo =
      data?.event_data?.repository?.repo_full_name

    const resource =
      data?.event_data?.resources?.[0]

    const digest = resource?.digest

    if(!repo || !digest){
      return res.status(200).send("ignored")
    }

    const project = repo.split("/")[0]
    const repository = repo.split("/").slice(1).join("/")

    console.log("Repository:", repo)
    console.log("Digest:", digest)

    const artifactUrl =
      `${HARBOR_URL}/api/v2.0/projects/${project}` +
      `/repositories/${repository}/artifacts/${digest}`

    let vulnPath = null
    let artifact = null

    // tenta até 10 vezes pegar o relatório
    for(let i=0;i<10;i++){

      const artifactResponse = await axios.get(
        artifactUrl,
        {
          auth:{
            username:HARBOR_USER,
            password:HARBOR_PASSWORD
          }
        }
      )

      artifact = artifactResponse.data

      vulnPath =
        artifact?.addition_links?.vulnerabilities?.href

      if(vulnPath){
        break
      }

      console.log("Vulnerability report not ready, retrying...")
      await sleep(3000)

    }

    if(!vulnPath){
      console.log("No vulnerability report found")
      return res.status(200).send("no report")
    }

    const vulnUrl =
      `${HARBOR_URL}${vulnPath}`

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

    if(report?.vulnerabilities){

      report.vulnerabilities.forEach(v=>{

        switch(v.severity){

          case "Critical":
            critical++
            break

          case "High":
            high++
            break

          case "Medium":
            medium++
            break

          case "Low":
            low++
            break

        }

      })

    }

    const total =
      critical + high + medium + low

    const teamsPayload = {

      text:
      `Harbor Vulnerability Scan\n\n`+
      `Repository: ${repo}\n`+
      `Digest: ${digest}\n\n`+
      `Critical: ${critical}\n`+
      `High: ${high}\n`+
      `Medium: ${medium}\n`+
      `Low: ${low}\n\n`+
      `Total: ${total}`

    }

    await axios.post(
      TEAMS_WEBHOOK,
      teamsPayload
    )

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
