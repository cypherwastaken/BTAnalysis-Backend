import * as acorn from "acorn"

function extractURLs(script) {
  const urlRegex = /(https?:\/\/[^\s"'`]+)/gi
  const matches = script.match(urlRegex) || []
  return [...new Set(matches)]
}

function extractRequires(script) {
  const requireRegex = /@require\s+([^\s]+)/g
  let match
  const results = []

  while ((match = requireRegex.exec(script)) !== null) {
    results.push(match[1])
  }

  return results
}

function entropy(str) {
  const map = {}
  for (const c of str) map[c] = (map[c] || 0) + 1
  const len = str.length

  return Object.values(map).reduce((acc, freq) => {
    const p = freq / len
    return acc - p * Math.log2(p)
  }, 0)
}

function detectHighEntropyStrings(script) {
  const strings = script.match(/["'`](.*?)["'`]/g) || []
  return strings.some(s => entropy(s) > 4.5 && s.length > 50)
}

function astScan(script) {
  const findings = {
    evalCall: false,
    functionConstructor: false,
    dynamicImport: false,
    scriptInjection: false,
    keylogger: false
  }

  try {
    const ast = acorn.parse(script, {
      ecmaVersion: "latest",
      sourceType: "script"
    })

    function walk(node) {
      if (!node) return

      switch (node.type) {
        case "CallExpression":
          if (node.callee.name === "eval") findings.evalCall = true

          if (
            node.callee.type === "MemberExpression" &&
            node.callee.property?.name === "addEventListener"
          ) {
            const arg = node.arguments?.[0]?.value
            if (["keydown", "keypress", "keyup"].includes(arg)) {
              findings.keylogger = true
            }
          }
          break

        case "NewExpression":
          if (node.callee.name === "Function")
            findings.functionConstructor = true
          break

        case "ImportExpression":
          findings.dynamicImport = true
          break
      }

      for (const key in node) {
        const value = node[key]
        if (Array.isArray(value)) value.forEach(walk)
        else if (value && typeof value === "object") walk(value)
      }
    }

    walk(ast)
  } catch (e) {
    findings.parseError = true
  }

  return findings
}

export default async function handler(req, res) {

  if (req.method !== "POST") {
    return res.status(405).json({ error: "POST only" })
  }

  const { script } = req.body

  if (!script) {
    return res.status(400).json({ error: "script required" })
  }

  const checks = {
    cookieAccess: /document\.cookie/i,
    localStorage: /localStorage/i,
    sessionStorage: /sessionStorage/i,
    websocket: /WebSocket/i,
    beacon: /sendBeacon/i,
    popup: /window\.open/i,
    redirect: /window\.location/i,
    miner: /(coinhive|cryptonight|miner)/i,
    base64: /(atob|btoa)\(/i,
    encodedBlob: /[A-Za-z0-9+/]{200,}/,
    dynamicScript: /createElement\(['"]script['"]\)/i
  }

  const results = {}
  let totalChecks = 0
  let passedChecks = 0

  for (const [name, regex] of Object.entries(checks)) {
    totalChecks++
    const detected = regex.test(script)

    results[name] = !detected

    if (!detected) passedChecks++
  }

  const astResults = astScan(script)

  for (const [name, detected] of Object.entries(astResults)) {
    totalChecks++
    results[`ast_${name}`] = !detected

    if (!detected) passedChecks++
  }

  totalChecks++
  const entropyDetected = detectHighEntropyStrings(script)
  results.highEntropyStrings = !entropyDetected
  if (!entropyDetected) passedChecks++

  const urls = extractURLs(script)

  const requires = extractRequires(script)

  const score = `${passedChecks}/${totalChecks}`

  return res.json({
    passed: passedChecks === totalChecks,
    score,
    passedChecks,
    totalChecks,
    urlsFound: urls,
    dependencies: requires,
    results
  })
}
