import { useEffect, useState } from "react";
import "./App.css";
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";

/* =========================================================
   API CONFIGURATION
========================================================= */

const API_BASE_URL = "http://127.0.0.1:5000";

/* =========================================================
   SECURITY RISK CLASSIFICATION
========================================================= */

function getRiskLevel(port) {
  if (!port || !port.risk) {
    return "LOW";
  }

  return String(port.risk).toUpperCase();
}

/* =========================================================
   CALCULATE RISK SUMMARY
========================================================= */

function calculateRiskSummary(portList) {
  const summary = {
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  if (!Array.isArray(portList)) {
    return summary;
  }

  portList.forEach((port) => {
    const risk = getRiskLevel(port).toLowerCase();

    if (risk === "high") {
      summary.high++;
    } else if (risk === "medium") {
      summary.medium++;
    } else if (
      risk === "info" ||
      risk === "informational"
    ) {
      summary.info++;
    } else {
      summary.low++;
    }
  });

  return summary;
}

/* =========================================================
   DEFAULT SETTINGS
========================================================= */

const DEFAULT_SETTINGS = {
  scanType: "Full TCP",
  customPorts: "",
  autoSaveHistory: true,
  showRiskAnalysis: true,
  showScanHistory: true,
};

/* =========================================================
   NORMALIZE PORT DATA
========================================================= */

function normalizePorts(ports) {
  if (Array.isArray(ports)) {
    return ports;
  }

  if (typeof ports === "string") {
    try {
      const parsed = JSON.parse(ports);

      return Array.isArray(parsed)
        ? parsed
        : [];
    } catch (error) {
      console.error(
        "Unable to parse historical port data:",
        error
      );

      return [];
    }
  }

  return [];
}

/* =========================================================
   FORMAT HISTORY DATA
========================================================= */

function formatHistoryItem(item) {
  const ports = normalizePorts(
    item?.ports
  );

  return {
    id: item?.id,

    target:
      item?.target ||
      "Unknown Target",

    ports,

    security: {
      high:
        Number(item?.high_risk) || 0,

      medium:
        Number(item?.medium_risk) || 0,

      low:
        Number(item?.low_risk) || 0,

      info:
        Number(item?.info_risk) || 0,

      total_open_ports:
        Number(item?.total_open_ports) ||
        ports.length,

      risk_level:
        item?.risk_level ||
        "LOW",

      recommendations:
        Array.isArray(
          item?.recommendations
        )
          ? item.recommendations
          : [],
    },

    scan_type:
      item?.scan_type ||
      "Full TCP",

    scan_duration:
      Number(item?.scan_duration) || 0,

    timestamp:
      item?.scan_date ||
      item?.created_at ||
      "",
  };
}

/* =========================================================
   MAIN APP
========================================================= */

function App() {

  /* =======================================================
     LOGIN STATE
  ======================================================= */

  const [isLoggedIn, setIsLoggedIn] = useState(
    localStorage.getItem("portScannerLoggedIn") === "true" &&
    !!localStorage.getItem("portScannerUserId")
  );

  const [isSignup, setIsSignup] = useState(false);

  const [username, setUsername] = useState("");

  const [password, setPassword] = useState("");

  const [confirmPassword, setConfirmPassword] = useState("");

  const [loginError, setLoginError] = useState("");

  const [signupError, setSignupError] = useState("");

  const [signupSuccess, setSignupSuccess] = useState("");

  const [verbosityTiming, setVerbosityTiming] = useState("T3");


  /* =======================================================
     LOGIN HANDLER
  ======================================================= */

  const handleLogin = async (e) => {
    e.preventDefault();

    setLoginError("");
    setSignupError("");
    setSignupSuccess("");

    if (!username.trim() || !password) {
      setLoginError("Please enter username and password.");
      return;
    }

    try {
      const response = await fetch(
        `${API_BASE_URL}/login`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            username,
            password,
          }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.error || "Login failed."
        );
      }

      localStorage.setItem(
        "user",
        JSON.stringify({
          id: data.user_id,
          username: data.username
        })
      );

      localStorage.setItem(
        "portScannerLoggedIn",
        "true"
      );

      localStorage.setItem(
        "portScannerUsername",
        data.username
      );

      localStorage.setItem(
        "portScannerUserId",
        data.user_id
      );

      setIsLoggedIn(true);
      setUsername("");
      setPassword("");
      setLoginError("");

    } catch (error) {
      console.error("Login error:", error);

      setLoginError(
        error.message ||
        "Unable to login."
      );
    }
  };

  const handleSignup = async (e) => {
    e.preventDefault();

    setSignupError("");
    setSignupSuccess("");

    if (!username.trim()) {
      setSignupError("Please enter a username.");
      return;
    }

    if (!password) {
      setSignupError("Please enter a password.");
      return;
    }

    if (password.length < 6) {
      setSignupError(
        "Password must contain at least 6 characters."
      );
      return;
    }

    if (password !== confirmPassword) {
      setSignupError(
        "Passwords do not match."
      );
      return;
    }

    try {
      const response = await fetch(
        `${API_BASE_URL}/signup`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            username: username.trim(),
            password: password,
          }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.error ||
          "Unable to create account."
        );
      }

      setSignupSuccess(
        "Account created successfully. Please login."
      );

      setUsername("");
      setPassword("");
      setConfirmPassword("");

      setTimeout(() => {
        setIsSignup(false);
        setSignupSuccess("");
      }, 1500);

    } catch (error) {
      console.error(
        "Signup error:",
        error
      );

      setSignupError(
        error.message ||
        "Unable to create account."
      );
    }
  };

  /* =======================================================
     LOGOUT
  ======================================================= */

  const handleLogout = () => {
    // Remove current user session
    localStorage.removeItem("user");
    localStorage.removeItem("portScannerUserId");
    localStorage.removeItem("portScannerUsername");
    localStorage.removeItem("portScannerLoggedIn");

    // Clear scanner data
    setHistory([]);
    setPorts([]);
    setSelectedHistory(null);
    setScannedTarget("");
    setTarget("");
    setSearchTerm("");
    setScanDuration(0);
    setError("");

    // Clear login state
    setIsLoggedIn(false);
    setUsername("");
    setPassword("");
  };


  /* =======================================================
     SCANNER STATE
  ======================================================= */

  const [target, setTarget] = useState("");

  const [ports, setPorts] = useState([]);

  const [loading, setLoading] = useState(false);

  const [error, setError] = useState("");

  const [scannedTarget, setScannedTarget] =
    useState("");

  const [scanDuration, setScanDuration] =
    useState(0);

  const [history, setHistory] =
    useState([]);

  const [selectedHistory, setSelectedHistory] =
    useState(null);

  const [selectedHistoryTarget, setSelectedHistoryTarget] =
    useState("ALL"); 

  const [searchTerm, setSearchTerm] =
    useState("");

  const [settings, setSettings] =
    useState(DEFAULT_SETTINGS);

  const [loggedInUsername, setLoggedInUsername] = 
    useState("");  

  
  /* =======================================================
    EMAIL REPORT STATE
  ======================================================= */

  const [emailRecipient, setEmailRecipient] =
    useState("");

  const [showEmailForm, setShowEmailForm] =
  useState(false);  

  const [emailSending, setEmailSending] =
    useState(false);

  const [emailMessage, setEmailMessage] =
    useState("");

  const [emailError, setEmailError] =
    useState("");  

  /* =======================================================
     LOAD SETTINGS
  ======================================================= */

  useEffect(() => {
    try {
      const storedUsername =
        localStorage.getItem("portScannerUsername") ||
        localStorage.getItem("username");

      if (storedUsername) {
        setLoggedInUsername(storedUsername);
      }

      const savedSettings =
        localStorage.getItem(
          "portScannerSettings"
        );

      if (savedSettings) {
        const parsedSettings =
          JSON.parse(savedSettings);

        setSettings({
          ...DEFAULT_SETTINGS,
          ...parsedSettings,
        });
      }
    } catch (error) {
      console.error(
        "Unable to load scanner settings:",
        error
      );

      setSettings(
        DEFAULT_SETTINGS
      );
    }
  }, []);

  /* =======================================================
     LOAD SCAN HISTORY FROM SUPABASE
  ======================================================= */

  useEffect(() => {
    if (isLoggedIn) {
      loadHistory();
    } else {
      setHistory([]);
    }
  }, [isLoggedIn]);

  /* =======================================================
     LOAD HISTORY
  ======================================================= */

  const loadHistory = async () => {
    try {
      const userId = localStorage.getItem("portScannerUserId");

      if (!userId) {
        console.error("User session not found.");
        setHistory([]);
        return [];
      }

      console.log("Loading history for user ID:", userId);

      const response = await fetch(
        `${API_BASE_URL}/history?user_id=${encodeURIComponent(userId)}`
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.error || "Unable to load scan history."
        );
      }

      const formattedHistory =
        Array.isArray(data.history)
          ? data.history.map(formatHistoryItem)
          : [];

      setHistory(formattedHistory);

      console.log(
        "User-specific scan history loaded:",
        formattedHistory
      );

      return formattedHistory;

    } catch (error) {
      console.error(
        "Unable to load scan history:",
        error
      );

      setHistory([]);
      return null;
    }
  };

  /* =======================================================
     REFRESH HISTORY
  ======================================================= */

  const refreshHistory = async () => {
    return await loadHistory();
  };

  /* =======================================================
     SECURITY RISK SUMMARY
  ======================================================= */

  const riskSummary =
    calculateRiskSummary(
      ports
    );

  /* =======================================================
     SECURITY SCORE
  ======================================================= */

  const calculateSecurityScore = () => {
    if (ports.length === 0) {
      return 100;
    }

    const HIGH_WEIGHT = 20;
    const MEDIUM_WEIGHT = 10;
    const LOW_WEIGHT = 2;

    const riskPoints =
      riskSummary.high *
        HIGH_WEIGHT +
      riskSummary.medium *
        MEDIUM_WEIGHT +
      riskSummary.low *
        LOW_WEIGHT;

    const maxRiskPoints =
      ports.length *
      HIGH_WEIGHT;

    if (maxRiskPoints === 0) {
      return 100;
    }

    const score =
      100 -
      (riskPoints /
        maxRiskPoints) *
        100;

    return Math.round(
      Math.max(
        0,
        Math.min(
          100,
          score
        )
      )
    );
  };

  const securityScore =
    calculateSecurityScore();

  /* =======================================================
     SCORE LABEL
  ======================================================= */

  const getScoreLabel = (
    score
  ) => {
    if (score >= 80) {
      return "Good";
    }

    if (score >= 60) {
      return "Moderate";
    }

    if (score >= 40) {
      return "Weak";
    }

    return "Critical";
  };

  /* =======================================================
     OVERALL RISK
  ======================================================= */

  const getOverallRisk = () => {
    if (riskSummary.high > 0) {
      return "HIGH";
    }

    if (riskSummary.medium > 0) {
      return "MEDIUM";
    }

    return "LOW";
  };


  /* =======================================================
     START SCAN
  ======================================================= */

  const handleScan = async () => {
    if (!target.trim()) {
      setError(
        "Please enter a target."
      );

      return;
    }

    const scanTarget =
      target.trim();

    setLoading(true);

    setError("");

    setPorts([]);

    setScannedTarget("");

    setSearchTerm("");

    setSelectedHistory(null);

    setScanDuration(0);

    const userId = localStorage.getItem("portScannerUserId");

    if (!userId) {
        setError("User session not found. Please log out and log in again.");
        return;
    }

    try {
      const response =
        await fetch(
          `${API_BASE_URL}/scan`,
          {
            method: "POST",

            headers: {
              "Content-Type":
                "application/json",
            },

            body: JSON.stringify({
              user_id: 
                localStorage.getItem("portScannerUserId"),

              target:
                target.trim(),

              scan_type:
                settings.scanType,
                
              custom_ports: 
                settings.customPorts || "",

               timing:
                settings.scanType === "Verbosity Scan"
                  ? verbosityTiming
                  : "T4" 
            }),
          }
        );

      const data =
        await response.json();

      if (!response.ok) {
        throw new Error(
          data.error ||
            "Scan failed."
        );
      }

      const scanPorts =
        normalizePorts(
          data.ports
        );

      setPorts(
        scanPorts
      );

      setScanDuration(
        Number(
          data.scan_duration
        ) || 0
      );

      setScannedTarget(
        data.target ||
          scanTarget
      );


      if (
        settings.autoSaveHistory
      ) {
        await refreshHistory();
      }
    } catch (error) {
      console.error(
        "Scan error:",
        error
      );

      setError(
        error.message ||
          "Unable to complete the scan."
      );
    } finally {
      setLoading(false);
    }
  };

  /* =======================================================
     LOAD HISTORY SCAN
  ======================================================= */

  const loadHistoryScan = (
    item
  ) => {
    if (!item) {
      return;
    }

    setSelectedHistory(
      item
    );


    setPorts([]);

    setScannedTarget("");

    setScanDuration(0);

    setTarget(
      item.target || ""
    );

    setSearchTerm("");

    setError("");

    setTimeout(() => {
      document
        .querySelector(
          ".history-details-panel"
        )
        ?.scrollIntoView({
          behavior:
            "smooth",
          block: "start",
        });
    }, 100);
  };

  /* =======================================================
     DELETE ONE HISTORY RECORD
  ======================================================= */

  const deleteHistoryScan =
    async (scanId) => {
      if (!scanId) {
        return;
      }

      try {
        const response =
          await fetch(
            `${API_BASE_URL}/history/${scanId}`,
            {
              method: "DELETE",
            }
          );

        const data =
          await response.json();

        if (!response.ok) {
          throw new Error(
            data.error ||
              "Unable to delete scan history."
          );
        }

        setHistory(
          (currentHistory) =>
            currentHistory.filter(
              (item) =>
                item.id !==
                scanId
            )
        );

        if (
          selectedHistory &&
          selectedHistory.id ===
            scanId
        ) {
          setSelectedHistory(
            null
          );
        }

        setError("");
      } catch (error) {
        console.error(
          "Unable to delete scan history:",
          error
        );

        setError(
          error.message ||
            "Unable to delete scan history."
        );
      }
    };

  /* =======================================================
     DELETE ALL HISTORY
  ======================================================= */

  const clearHistory =
    async () => {
      if (
        history.length === 0
      ) {
        return;
      }

      const confirmed =
        window.confirm(
          "Are you sure you want to clear all scan history? This cannot be undone."
        );

      if (!confirmed) {
        return;
      }

      try {
        const response =
          await fetch(
            `${API_BASE_URL}/history`,
            {
              method: "DELETE",
            }
          );

        const data =
          await response.json();

        if (!response.ok) {
          throw new Error(
            data.error ||
              "Unable to clear scan history."
          );
        }

        setHistory([]);

        setSelectedHistory(
          null
        );

        setError("");

        console.log(
          "All scan history cleared."
        );
      } catch (error) {
        console.error(
          "Unable to clear scan history:",
          error
        );

        setError(
          error.message ||
            "Unable to clear scan history."
        );
      }
    };

  /* =======================================================
     DOWNLOAD HTML REPORT
  ======================================================= */

  const downloadScanReport =
    () => {
      if (
        !scannedTarget ||
        ports.length === 0
      ) {
        setError(
          "Please complete a scan before downloading the report."
        );

        return;
      }

      const reportDate =
        new Date().toLocaleString();

      const recommendations =
        [];

      if (
        riskSummary.high > 0
      ) {
        recommendations.push(
          "Immediately review and secure all high-risk services."
        );
      }

      if (
        riskSummary.medium > 0
      ) {
        recommendations.push(
          "Review medium-risk services and disable unnecessary exposure."
        );
      }

      if (
        riskSummary.low > 0
      ) {
        recommendations.push(
          "Review low-risk services and ensure they are intentionally exposed."
        );
      }

      if (
        riskSummary.high ===
          0 &&
        riskSummary.medium ===
          0
      ) {
        recommendations.push(
          "No high or medium-risk ports were detected."
        );
      }

      recommendations.push(
        "Close unused ports and services whenever possible."
      );

      recommendations.push(
        "Restrict sensitive services using firewall rules and access controls."
      );

      const overallRisk =
        getOverallRisk();

      const assessment =
        overallRisk ===
        "HIGH"
          ? "HIGH RISK"
          : overallRisk ===
            "MEDIUM"
          ? "MODERATE RISK"
          : "LOW RISK";

      const escapeHtml =
        (value) => {
          return String(
            value ?? ""
          )
            .replace(
              /&/g,
              "&amp;"
            )
            .replace(
              /</g,
              "&lt;"
            )
            .replace(
              />/g,
              "&gt;"
            )
            .replace(
              /"/g,
              "&quot;"
            )
            .replace(
              /'/g,
              "&#039;"
            );
        };

      const portRows =
        ports
          .map((port) => {
            const risk =
              getRiskLevel(
                port
              );

            return `
              <tr>
                <td>${escapeHtml(
                  port.port
                )}</td>

                <td>${escapeHtml(
                  String(
                    port.protocol ||
                      ""
                  ).toUpperCase()
                )}</td>

                <td>${escapeHtml(
                  port.state ||
                    ""
                )}</td>

                <td>${escapeHtml(
                  port.service ||
                    "Unknown"
                )}</td>

                <td class="risk-${risk.toLowerCase()}">
                  ${escapeHtml(
                    risk
                  )}
                </td>
              </tr>
            `;
          })
          .join("");

      const recommendationList =
        recommendations
          .map(
            (
              recommendation
            ) =>
              `<li>${escapeHtml(
                recommendation
              )}</li>`
          )
          .join("");

      const reportHtml = `
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width, initial-scale=1.0">

<title>
Security Scan Report -
${escapeHtml(
  scannedTarget
)}
</title>

<style>

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  padding: 40px;

  font-family:
    Arial,
    Helvetica,
    sans-serif;

  background: #f1f5f9;
  color: #1e293b;
}

.container {
  max-width: 1100px;
  margin: auto;

  background: white;

  padding: 40px;

  border-radius: 12px;

  box-shadow:
    0 10px 30px
    rgba(0, 0, 0, 0.08);
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;

  padding-bottom: 25px;

  border-bottom:
    2px solid #e2e8f0;
}

.logo {
  color: #2563eb;

  font-size: 14px;
  font-weight: 800;

  letter-spacing: 2px;
}

h1 {
  margin: 8px 0 5px;

  font-size: 28px;

  color: #0f172a;
}

.subtitle {
  color: #64748b;

  font-size: 13px;
}

.report-date {
  text-align: right;

  color: #64748b;

  font-size: 12px;
}

.summary-grid {
  display: grid;

  grid-template-columns:
    repeat(4, 1fr);

  gap: 15px;

  margin: 30px 0;
}

.summary-card {
  padding: 20px;

  border:
    1px solid #e2e8f0;

  border-radius: 8px;

  background: #f8fafc;
}

.summary-card span {
  display: block;

  color: #64748b;

  font-size: 11px;
  font-weight: 700;

  text-transform: uppercase;
}

.summary-card strong {
  display: block;

  margin-top: 8px;

  font-size: 26px;
}

.high {
  color: #dc2626;
}

.medium {
  color: #ea580c;
}

.low {
  color: #16a34a;
}

.info {
  color: #2563eb;
}

.score-box {
  margin: 25px 0;

  padding: 25px;

  border-radius: 10px;

  background: #0f172a;

  color: white;
}

.score-box h2 {
  margin: 0 0 8px;

  font-size: 14px;
}

.score {
  font-size: 36px;

  font-weight: 800;
}

.assessment {
  margin-top: 5px;

  color: #94a3b8;

  font-size: 13px;
}

.section {
  margin-top: 35px;
}

.section h2 {
  margin-bottom: 15px;

  font-size: 18px;

  color: #0f172a;
}

table {
  width: 100%;

  border-collapse: collapse;
}

th {
  padding: 12px;

  background: #0f172a;

  color: white;

  text-align: left;

  font-size: 11px;
}

td {
  padding: 11px 12px;

  border-bottom:
    1px solid #e2e8f0;

  font-size: 12px;
}

.risk-high {
  color: #dc2626;

  font-weight: 800;
}

.risk-medium {
  color: #ea580c;

  font-weight: 800;
}

.risk-low {
  color: #16a34a;

  font-weight: 800;
}

.risk-info {
  color: #2563eb;

  font-weight: 800;
}

.recommendations {
  padding: 20px;

  background: #f8fafc;

  border:
    1px solid #e2e8f0;

  border-radius: 8px;
}

.recommendations li {
  margin-bottom: 10px;

  color: #475569;

  font-size: 13px;
}

.footer {
  margin-top: 40px;

  padding-top: 20px;

  border-top:
    1px solid #e2e8f0;

  color: #94a3b8;

  font-size: 11px;

  text-align: center;
}

@media print {

  body {
    padding: 0;

    background: white;
  }

  .container {
    box-shadow: none;

    max-width: none;
  }

}

</style>

</head>

<body>

<div class="container">

  <div class="header">

    <div>

      <div class="logo">
        SECURITY SCANNER
      </div>

      <h1>
        Network Security Scan Report
      </h1>

      <div class="subtitle">
        Comprehensive TCP Port Security Assessment
      </div>

    </div>

    <div class="report-date">

      <strong>
        Scan Date
      </strong>

      <br>

      ${escapeHtml(
        reportDate
      )}

    </div>

  </div>

  <div class="section">

    <h2>
      Scan Information
    </h2>

    <p>
      <strong>
        Target:
      </strong>

      ${escapeHtml(
        scannedTarget
      )}
    </p>

    <p>
      <strong>
        Scan Type:
      </strong>

      ${escapeHtml(
        settings.scanType
      )}
    </p>

    <p>
      <strong>
        Scan Duration:
      </strong>

      ${escapeHtml(
        scanDuration
      )} sec
    </p>

    <p>
      <strong>
        Total Open Ports:
      </strong>

      ${ports.length}

    </p>

  </div>

  <div class="summary-grid">

    <div class="summary-card">

      <span>
        High Risk
      </span>

      <strong class="high">
        ${riskSummary.high}
      </strong>

    </div>

    <div class="summary-card">

      <span>
        Medium Risk
      </span>

      <strong class="medium">
        ${riskSummary.medium}
      </strong>

    </div>

    <div class="summary-card">

      <span>
        Low Risk
      </span>

      <strong class="low">
        ${riskSummary.low}
      </strong>

    </div>

    <div class="summary-card">

      <span>
        Informational
      </span>

      <strong class="info">
        ${riskSummary.info}
      </strong>

    </div>

  </div>

  <div class="score-box">

    <h2>
      SECURITY SCORE
    </h2>

    <div class="score">
      ${securityScore}/100
    </div>

    <div class="assessment">

      Overall Assessment:
      ${assessment}

    </div>

  </div>

  <div class="section">

    <h2>
      Open Ports
    </h2>

    <table>

      <thead>

        <tr>

          <th>Port</th>

          <th>Protocol</th>

          <th>State</th>

          <th>Service</th>

          <th>Risk</th>

        </tr>

      </thead>

      <tbody>

        ${portRows}

      </tbody>

    </table>

  </div>

  <div class="section">

    <h2>
      Security Recommendations
    </h2>

    <div class="recommendations">

      <ul>

        ${recommendationList}

      </ul>

    </div>

  </div>

  <div class="footer">

    Generated by Security Scanner

    <br>

    Nmap-based Network Security Assessment

  </div>

</div>

</body>

</html>
`;

      const blob =
        new Blob(
          [reportHtml],
          {
            type:
              "text/html;charset=utf-8",
          }
        );

      const url =
        URL.createObjectURL(
          blob
        );

      const link =
        document.createElement(
          "a"
        );

      link.href = url;

      link.download =
        `security-scan-report-${scannedTarget.replace(
          /[^a-z0-9.-]/gi,
          "_"
        )}.html`;

      document.body.appendChild(
        link
      );

      link.click();

      document.body.removeChild(
        link
      );

      URL.revokeObjectURL(
        url
      );
    };

  /* =======================================================
     DOWNLOAD PDF REPORT
  ======================================================= */

  const downloadPdfReport =
    () => {
      if (
        !scannedTarget ||
        ports.length === 0
      ) {
        setError(
          "Please complete a scan before downloading the PDF report."
        );

        return;
      }

      const doc =
        new jsPDF();

      const reportDate =
        new Date().toLocaleString();

      const overallRisk =
        getOverallRisk();

      const assessment =
        overallRisk ===
        "HIGH"
          ? "HIGH RISK"
          : overallRisk ===
            "MEDIUM"
          ? "MODERATE RISK"
          : "LOW RISK";

      /* =====================================================
         HEADER
      ===================================================== */

      doc.setFontSize(
        18
      );

      doc.setFont(
        "helvetica",
        "bold"
      );

      doc.text(
        "SECURITY SCANNER",
        20,
        20
      );

      doc.setFontSize(
        14
      );

      doc.text(
        "Network Security Scan Report",
        20,
        30
      );

      doc.setFontSize(
        9
      );

      doc.setFont(
        "helvetica",
        "normal"
      );

      doc.text(
        `Scan Date: ${reportDate}`,
        20,
        38
      );

      /* =====================================================
         SCAN INFORMATION
      ===================================================== */

      doc.setFontSize(
        12
      );

      doc.setFont(
        "helvetica",
        "bold"
      );

      doc.text(
        "Scan Information",
        20,
        52
      );

      doc.setFontSize(
        10
      );

      doc.setFont(
        "helvetica",
        "normal"
      );

      doc.text(
        `Target: ${scannedTarget}`,
        20,
        60
      );

      doc.text(
        `Scan Type: ${settings.scanType}`,
        20,
        67
      );

      doc.text(
        `Scan Duration: ${scanDuration} sec`,
        20,
        74
      );

      doc.text(
        `Total Open Ports: ${ports.length}`,
        20,
        81
      );

      /* =====================================================
         SECURITY ASSESSMENT
      ===================================================== */

      doc.setFontSize(
        12
      );

      doc.setFont(
        "helvetica",
        "bold"
      );

      doc.text(
        "Security Assessment",
        20,
        95
      );

      doc.setFontSize(
        10
      );

      doc.setFont(
        "helvetica",
        "normal"
      );

      doc.text(
        `High Risk: ${riskSummary.high}`,
        20,
        103
      );

      doc.text(
        `Medium Risk: ${riskSummary.medium}`,
        20,
        110
      );

      doc.text(
        `Low Risk: ${riskSummary.low}`,
        20,
        117
      );

      doc.text(
        `Informational: ${riskSummary.info}`,
        20,
        124
      );

      doc.setFont(
        "helvetica",
        "bold"
      );

      doc.text(
        `Security Score: ${securityScore}/100`,
        20,
        134
      );

      doc.text(
        `Overall Assessment: ${assessment}`,
        20,
        141
      );

      /* =====================================================
         OPEN PORTS TABLE
      ===================================================== */

      const tableData =
        ports.map(
          (port) => [
            port.port,

            String(
              port.protocol ||
                ""
            ).toUpperCase(),

            port.state ||
              "",

            port.service ||
              "Unknown",

            getRiskLevel(
              port
            ),
          ]
        );

      autoTable(doc, {
        startY: 152,

        head: [
          [
            "Port",
            "Protocol",
            "State",
            "Service",
            "Risk",
          ],
        ],

        body:
          tableData,

        theme:
          "grid",

        styles: {
          fontSize: 9,

          cellPadding: 3,
        },

        headStyles: {
          fontStyle:
            "bold",
        },

        margin: {
          left: 20,
          right: 20,
        },
      });

      /* =====================================================
         RECOMMENDATIONS
      ===================================================== */

      let recommendationStart =
        doc.lastAutoTable.finalY +
        15;

      if (
        recommendationStart >
        250
      ) {
        doc.addPage();

        recommendationStart =
          20;
      }

      doc.setFontSize(
        12
      );

      doc.setFont(
        "helvetica",
        "bold"
      );

      doc.text(
        "Security Recommendations",
        20,
        recommendationStart
      );

      recommendationStart +=
        8;

      doc.setFontSize(
        9
      );

      doc.setFont(
        "helvetica",
        "normal"
      );

      const recommendations =
        [];

      if (
        riskSummary.high > 0
      ) {
        recommendations.push(
          "Immediately review and secure all high-risk services."
        );
      }

      if (
        riskSummary.medium >
        0
      ) {
        recommendations.push(
          "Review medium-risk services and disable unnecessary exposure."
        );
      }

      if (
        riskSummary.low > 0
      ) {
        recommendations.push(
          "Review low-risk services and ensure they are intentionally exposed."
        );
      }

      if (
        riskSummary.high ===
          0 &&
        riskSummary.medium ===
          0
      ) {
        recommendations.push(
          "No high or medium-risk ports were detected."
        );
      }

      recommendations.push(
        "Close unused ports and services whenever possible."
      );

      recommendations.push(
        "Restrict sensitive services using firewall rules and access controls."
      );

      recommendations.forEach(
        (
          recommendation
        ) => {
          const lines =
            doc.splitTextToSize(
              `• ${recommendation}`,
              170
            );

          if (
            recommendationStart +
              lines.length *
                5 >
            275
          ) {
            doc.addPage();

            recommendationStart =
              20;
          }

          doc.text(
            lines,
            20,
            recommendationStart
          );

          recommendationStart +=
            lines.length *
              5 +
            3;
        }
      );

      /* =====================================================
         FOOTER
      ===================================================== */

      const pageCount =
        doc.getNumberOfPages();

      for (
        let page = 1;
        page <= pageCount;
        page++
      ) {
        doc.setPage(
          page
        );

        const pageHeight =
          doc.internal
            .pageSize
            .height;

        doc.setFontSize(
          8
        );

        doc.setFont(
          "helvetica",
          "normal"
        );

        doc.text(
          "Generated by Security Scanner",
          20,
          pageHeight - 15
        );

        doc.text(
          "Nmap-based Network Security Assessment",
          20,
          pageHeight - 10
        );

        doc.text(
          `Page ${page} of ${pageCount}`,
          170,
          pageHeight - 10
        );
      }

      /* =====================================================
         SAVE PDF
      ===================================================== */

      const safeTarget =
        scannedTarget.replace(
          /[^a-z0-9.-]/gi,
          "_"
        );

      doc.save(
        `security-scan-report-${safeTarget}.pdf`
      );
    };


  /* =======================================================
    EMAIL SECURITY REPORT
  ======================================================= */

  const handleEmailReport = async () => {
    setEmailMessage("");
    setEmailError("");

    // Check scan
    if (!scannedTarget || ports.length === 0) {
      setEmailError("Please complete a scan before sending the report.");
      return;
    }

    // Check email
    const recipient = emailRecipient.trim();

    if (!recipient) {
      setEmailError("Please enter a recipient email address.");
      return;
    }

    // Correct email validation regex
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailPattern.test(recipient)) {
      setEmailError("Please enter a valid email address.");
      return;
    }

    setEmailSending(true);

    try {
      const recommendations = [];

      if (riskSummary.high > 0) {
        recommendations.push(
          "Immediately review and secure all high-risk services."
        );
      }

      if (riskSummary.medium > 0) {
        recommendations.push(
          "Review medium-risk services and disable unnecessary exposure."
        );
      }

      if (riskSummary.low > 0) {
        recommendations.push(
          "Review low-risk services and ensure they are intentionally exposed."
        );
      }

      if (riskSummary.high === 0 && riskSummary.medium === 0) {
        recommendations.push(
          "No high or medium-risk ports were detected."
        );
      }

      recommendations.push(
        "Close unused ports and services whenever possible."
      );

      recommendations.push(
        "Restrict sensitive services using firewall rules and access controls."
      );

      const overallRisk = getOverallRisk();

      const assessment =
        overallRisk === "HIGH"
          ? "HIGH RISK"
          : overallRisk === "MEDIUM"
          ? "MODERATE RISK"
          : "LOW RISK";


      const response = await fetch(
        `${API_BASE_URL}/email-report`,
        {
          method: "POST",

          headers: {
            "Content-Type": "application/json",
          },

          body: JSON.stringify({
            recipient: recipient,
            target: scannedTarget,

            scan_type: settings.scanType,
            scan_duration: scanDuration,

            total_open_ports: ports.length,

            ports: ports,

            risk_summary: {
              high: riskSummary.high,
              medium: riskSummary.medium,
              low: riskSummary.low,
              info: riskSummary.info,
            },

            security_score: securityScore,

            overall_risk: overallRisk,

            assessment: assessment,

            recommendations: recommendations,

            scan_date: new Date().toLocaleString(),
          }),
        }
      );

      const contentType = response.headers.get("content-type") || "";

      let data = {};

      if (contentType.includes("application/json")) {
        data = await response.json();
      } else {
        const text = await response.text();

        data = {
          error: text || "Server returned an unexpected response.",
        };
      }

      if (!response.ok) {
        throw new Error(
          data.error || "Unable to send email report."
        );
      }

      setEmailMessage(
        data.message || "Security report sent successfully."
      );

      setEmailError("");

    } catch (error) {
      console.error("Email report error:", error);

      if (error instanceof TypeError && error.message === "Failed to fetch") {
        setEmailError(
          "Unable to connect to the backend. Please make sure the Python API is running on http://127.0.0.1:5000."
        );
      } else {
        setEmailError(
          error.message || "Unable to send email report."
        );
      }

      setEmailMessage("");

    } finally {
      setEmailSending(false);
    }
  };
  
  
  /* =======================================================
     UPDATE SETTINGS
  ======================================================= */

  const updateSetting =
    (
      key,
      value
    ) => {
      const updatedSettings =
        {
          ...settings,
          [key]: value,
        };

      setSettings(
        updatedSettings
      );

      localStorage.setItem(
        "portScannerSettings",
        JSON.stringify(
          updatedSettings
        )
      );
    };


    /* =======================================================
    LOGIN SCREEN
    ======================================================= */

    if (!isLoggedIn) {
      return (
        <div className="login-page">

          <div className="login-card">

            <div className="login-icon">
              🛡️
            </div>

            {!isSignup ? (
              <>
                {/* =========================
                    LOGIN
                ========================= */}

                <h1>
                  SECURITY SCANNER
                </h1>

                <p className="login-subtitle">
                  Advanced Network Security Tool
                </p>

                <form onSubmit={handleLogin}>

                  <div className="login-field">

                    <label>
                      Username
                    </label>

                    <input
                      type="text"
                      value={username}
                      onChange={(e) => {
                        setUsername(e.target.value);
                        setLoginError("");
                      }}
                      placeholder="Enter username"
                      autoComplete="username"
                    />

                  </div>

                  <div className="login-field">

                    <label>
                      Password
                    </label>

                    <input
                      type="password"
                      value={password}
                      onChange={(e) => {
                        setPassword(e.target.value);
                        setLoginError("");
                      }}
                      placeholder="Enter password"
                      autoComplete="current-password"
                    />

                  </div>

                  {loginError && (
                    <div className="login-error">
                      ⚠ {loginError}
                    </div>
                  )}

                  <button
                    type="submit"
                    className="login-button"
                  >
                    LOGIN
                  </button>

                </form>

                <div className="login-switch">

                  <span>
                    Don't have an account?
                  </span>

                  <button
                    type="button"
                    onClick={() => {
                      setIsSignup(true);
                      setLoginError("");
                      setUsername("");
                      setPassword("");
                    }}
                  >
                    Create an account
                  </button>

                </div>

              </>
            ) : (
              <>
                {/* =========================
                    SIGNUP
                ========================= */}

                <h1>
                  CREATE ACCOUNT
                </h1>

                <p className="login-subtitle">
                  Register for Security Scanner
                </p>

                <form onSubmit={handleSignup}>

                  <div className="login-field">

                    <label>
                      Username
                    </label>

                    <input
                      type="text"
                      value={username}
                      onChange={(e) => {
                        setUsername(e.target.value);
                        setSignupError("");
                      }}
                      placeholder="Choose a username"
                      autoComplete="username"
                    />

                  </div>

                  <div className="login-field">

                    <label>
                      Password
                    </label>

                    <input
                      type="password"
                      value={password}
                      onChange={(e) => {
                        setPassword(e.target.value);
                        setSignupError("");
                      }}
                      placeholder="Minimum 6 characters"
                      autoComplete="new-password"
                    />

                  </div>

                  <div className="login-field">

                    <label>
                      Confirm Password
                    </label>

                    <input
                      type="password"
                      value={confirmPassword}
                      onChange={(e) => {
                        setConfirmPassword(e.target.value);
                        setSignupError("");
                      }}
                      placeholder="Re-enter password"
                      autoComplete="new-password"
                    />

                  </div>

                  {signupError && (
                    <div className="login-error">
                      ⚠ {signupError}
                    </div>
                  )}

                  {signupSuccess && (
                    <div className="login-success">
                      ✓ {signupSuccess}
                    </div>
                  )}

                  <button
                    type="submit"
                    className="login-button"
                  >
                    CREATE ACCOUNT
                  </button>

                </form>

                <div className="login-switch">

                  <span>
                    Already have an account?
                  </span>

                  <button
                    type="button"
                    onClick={() => {
                      setIsSignup(false);
                      setSignupError("");
                      setSignupSuccess("");
                      setUsername("");
                      setPassword("");
                      setConfirmPassword("");
                    }}
                  >
                    Back to Login
                  </button>

                </div>

              </>
            )}

          </div>

        </div>
      );
    }

    /* =======================================================
      FILTER HISTORY
    ======================================================= */

    const filteredHistory = history.filter((item) => {
      const itemTarget = String(
        item.target || ""
      )
        .trim()
        .toLowerCase();

      const selectedTarget = String(
        selectedHistoryTarget || "ALL"
      )
        .trim()
        .toLowerCase();

      const search = String(
        searchTerm || ""
      )
        .trim()
        .toLowerCase();

      const matchesTarget =
        selectedTarget === "all" ||
        itemTarget === selectedTarget;

      const matchesSearch =
        itemTarget.includes(search);

      return (
        matchesTarget &&
        matchesSearch
      );
    });

    /* =======================================================
      FILTER PORTS
    ======================================================= */

    const filteredPorts =
      ports.filter(
        (port) => {
          const portNumber =
            String(
              port.port || ""
            );

          const service =
            String(
              port.service || ""
            ).toLowerCase();

          const search =
            searchTerm.toLowerCase();

          return (
            portNumber.includes(search) ||
            service.includes(search)
          );
        }
      );

    
    /* =======================================================
      HISTORY TARGET FILTER
    ======================================================= */

    const historyTargets = [
      "ALL",
      ...Array.from(
        new Set(
          history
            .map((item) => String(item.target || "").trim())
            .filter(Boolean)
        )
      ),
    ];    


    /* =======================================================
      MAIN DASHBOARD
    ======================================================= */

    return (
      <div className="app">
  

      {/* =================================================
          SIDEBAR
      ================================================= */}

      <aside className="sidebar">

        <div className="logo">

          <div className="logo-icon">
            🛡️
          </div>

          <div>

            <h2>
              SECURITY SCANNER
            </h2>

            <span>
              Advanced Network Tool
            </span>

          </div>

        </div>

        {/* NAVIGATION */}

        <nav className="navigation">

          <button
            className="nav-item active"
            onClick={() =>
              window.scrollTo({
                top: 0,
                behavior:
                  "smooth",
              })
            }
          >
            <span>⌂</span>
            Dashboard
          </button>

          <button
            className="nav-item"
            onClick={() => {
              document
                .querySelector(
                  ".scanner-card"
                )
                ?.scrollIntoView({
                  behavior:
                    "smooth",
                });
            }}
          >
            <span>◉</span>
            Port Scanner
          </button>

          <button
            className="nav-item"
            onClick={() => {
              document
                .querySelector(
                  ".history-section"
                )
                ?.scrollIntoView({
                  behavior:
                    "smooth",
                });
            }}
          >
            <span>▣</span>
            Scan History
          </button>

          <button
            className="nav-item"
            onClick={() => {
              document
                .querySelector(
                  ".settings-section"
                )
                ?.scrollIntoView({
                  behavior:
                    "smooth",
                });
            }}
          >
            <span>⚙</span>
            Settings
          </button>

        </nav>

        {/* SIDEBAR FOOTER */}

        <div className="sidebar-footer">

          <div className="backend-status">

            <span className="online-dot"></span>

            Backend Online

          </div>

          <small>
            Flask API • Port 5000
          </small>

          <div className="logged-in-user">

            <span className="user-icon">👤</span>

            <span className="username-text">
              {loggedInUsername || "User"}
            </span>

          </div>

          <button
            className="logout-button"
            onClick={handleLogout}
          >
            ⇥ Logout
          </button>

        </div>

      </aside>

      {/* =================================================
          MAIN CONTENT
      ================================================= */}

      <main className="main-content">

        {/* =================================================
            TOP BAR
        ================================================= */}

        <header className="topbar">

          <div>

            <h1>
              Network Security Dashboard
            </h1>

            <p>
              Monitor and analyze open network ports
            </p>

          </div>

          <div className="connection-status">

            <span className="online-dot"></span>

            System Online

          </div>

        </header>

        {/* =================================================
            SCANNER CARD
        ================================================= */}

        <section className="scanner-card">

          <div className="section-title">

            <div>

              <span className="eyebrow">
                NETWORK ANALYSIS
              </span>

              <h2>
                Start a Security Scan
              </h2>

            </div>

            <span className="scan-type">
              NMAP •{" "}
              {settings.scanType.toUpperCase()}
            </span>

          </div>

          {/* SCAN FORM */}

          <div className="scan-form">

            <div className="input-wrapper">

              <span className="input-icon">
                ⌕
              </span>

              <input
                type="text"
                value={target}
                onChange={(e) => {
                  setTarget(
                    e.target.value
                  );

                  if (error) {
                    setError("");
                  }
                }}
                onKeyDown={(e) => {
                  if (
                    e.key ===
                    "Enter"
                  ) {
                    handleScan();
                  }
                }}
                placeholder="Enter IP address or hostname"
                disabled={loading}
              />

            </div>

            <button
              className="scan-button"
              onClick={
                handleScan
              }
              disabled={
                  loading ||
                  (
                    settings.scanType === "Custom Ports" &&
                    !settings.customPorts.trim()
                  )
              }
            >

              {loading ? (
                <>
                  <span className="spinner"></span>

                  Scanning...
                </>
              ) : (
                "Start Scan"
              )}

            </button>

          </div>

          {error && (
            <div className="error-message">
              ⚠ {error}
            </div>
          )}

        </section>

        {/* =================================================
            STATISTICS
        ================================================= */}

        {scannedTarget && (
          <div className="stats-grid">

            <div className="stat-card">

              <div className="stat-icon blue">
                ◉
              </div>

              <div>

                <span>
                  TARGET
                </span>

                <strong className="target-value">
                  {scannedTarget}
                </strong>

              </div>

            </div>

            <div className="stat-card">

              <div className="stat-icon green">
                ✓
              </div>

              <div>

                <span>
                  OPEN PORTS
                </span>

                <strong>
                  {ports.length}
                </strong>

              </div>

            </div>

            <div className="stat-card">

              <div className="stat-icon orange">
                ⚡
              </div>

              <div>

                <span>
                  SCAN TYPE
                </span>

                <strong>
                  {settings.scanType}
                </strong>

              </div>

            </div>

            <div className="stat-card">

              <div className="stat-icon purple">
                ◷
              </div>

              <div>

                <span>
                  HISTORY
                </span>

                <strong>
                  {history.length}
                </strong>

              </div>

            </div>

            <div className="stat-card">

              <div className="stat-icon blue">
                ⏱
              </div>

              <div>

                <span>
                  SCAN DURATION
                </span>

                <strong>
                  {scanDuration} sec
                </strong>

              </div>

            </div>

          </div>
        )}

        {settings.scanType === "Verbosity Scan" && (
          <div>
            <strong>Timing:</strong>{" "}
            {verbosityTiming}
          </div>
        )}

        {/* =================================================
            SECURITY SCORE
        ================================================= */}

        {scannedTarget && (
          <section className="security-score-card">

            <div className="score-info">

              <span className="score-label">
                Security Score
              </span>

              <strong className="score-value">

                {securityScore}

                <span>
                  /100
                </span>

              </strong>

              <p className="score-description">

                {getScoreLabel(
                  securityScore
                )}

                {" — Overall Risk: "}

                {getOverallRisk()}

              </p>

            </div>

            <div className="score-progress">

              <div
                className="score-progress-bar"
                style={{
                  width:
                    `${securityScore}%`,
                }}
              ></div>

            </div>

          </section>
        )}

        {/* =================================================
            PORT RESULTS
        ================================================= */}

        {scannedTarget && (
          <section className="results-section">

            <div className="results-header">

              <div>

                <span className="eyebrow">
                  SCAN OUTPUT
                </span>

                <h2>
                  Open Ports
                </h2>

                <p>
                  Target:{" "}
                  <strong>
                    {scannedTarget}
                  </strong>
                </p>

              </div>

              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "8px",
                  flexWrap: "wrap",
                }}
              >

                <button
                  className="report-button"
                  onClick={downloadScanReport}
                >
                  ↓ HTML Report
                </button>

                <button
                  className="report-button"
                  onClick={downloadPdfReport}
                >
                  ↓ PDF Report
                </button>

                <button
                  type="button"
                  className="report-button"
                  onClick={() => {
                    setShowEmailForm((current) => !current);
                    setEmailError("");
                    setEmailMessage("");
                  }}
                >
                  ✉ Email Report
                </button>

                <span className="results-count">
                  {ports.length}{" "}
                  Open Port
                  {ports.length !== 1 ? "s" : ""}
                </span>

              </div>

            </div>

          {/* =================================================
              EMAIL REPORT
          ================================================= */}

          {showEmailForm && (
            <div
              style={{
                marginTop: "15px",
                padding: "18px",
                border: "1px solid #334155",
                borderRadius: "8px",
                background: "#0f172a",
              }}
            >

              <div
                style={{
                  marginBottom: "10px",
                  color: "#e2e8f0",
                  fontSize: "14px",
                  fontWeight: "600",
                }}
              >
                Email Security Report
              </div>

              <div
                style={{
                  display: "flex",
                  gap: "10px",
                  alignItems: "center",
                  flexWrap: "wrap",
                }}
              >

                <input
                  type="email"
                  value={emailRecipient}
                  onChange={(e) => {
                    setEmailRecipient(e.target.value);
                    setEmailError("");
                    setEmailMessage("");
                  }}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      handleEmailReport();
                    }
                  }}
                  placeholder="Enter recipient email address"
                  disabled={emailSending}
                  style={{
                    flex: "1",
                    minWidth: "260px",
                    padding: "10px 12px",
                    borderRadius: "6px",
                    border: "1px solid #475569",
                    background: "#020617",
                    color: "#ffffff",
                    outline: "none",
                  }}
                />

                <button
                  type="button"
                  className="report-button"
                  onClick={handleEmailReport}
                  disabled={
                    emailSending ||
                    !emailRecipient.trim()
                  }
                >
                  {emailSending
                    ? "Sending..."
                    : "✉ Send Report"}
                </button>

                <button
                  type="button"
                  className="report-button"
                  onClick={() => {
                    setShowEmailForm(false);
                    setEmailRecipient("");
                    setEmailError("");
                    setEmailMessage("");
                  }}
                  disabled={emailSending}
                >
                  Cancel
                </button>

              </div>

              {emailMessage && (
                <div
                  style={{
                    marginTop: "12px",
                    padding: "10px",
                    borderRadius: "6px",
                    background: "#052e16",
                    color: "#4ade80",
                    fontSize: "13px",
                  }}
                >
                  ✓ {emailMessage}
                </div>
              )}

              {emailError && (
                <div
                  style={{
                    marginTop: "12px",
                    padding: "10px",
                    borderRadius: "6px",
                    background: "#450a0a",
                    color: "#f87171",
                    fontSize: "13px",
                  }}
                >
                  ⚠ {emailError}
                </div>
              )}

            </div>
          )}
          
            
            {/* SEARCH */}

            <div className="table-toolbar">

              <div className="search-box">

                <span>
                  ⌕
                </span>

                <input
                  type="text"
                  placeholder="Search ports or services..."
                  value={
                    searchTerm
                  }
                  onChange={(
                    e
                  ) =>
                    setSearchTerm(
                      e.target.value
                    )
                  }
                />

              </div>

            </div>

            {/* TABLE */}

            <div className="table-container">

              {filteredPorts.length >
              0 ? (

                <table>

                  <thead>

                    <tr>

                      <th>
                        PORT
                      </th>

                      <th>
                        PROTOCOL
                      </th>

                      <th>
                        STATE
                      </th>

                      <th>
                        SERVICE
                      </th>

                      <th>
                        RISK
                      </th>

                    </tr>

                  </thead>

                  <tbody>

                    {filteredPorts.map(
                      (port) => {

                        const risk =
                          getRiskLevel(
                            port
                          );

                        return (
                          <tr
                            key={`${port.port}-${port.protocol}`}
                          >

                            <td className="port-number">
                              {
                                port.port
                              }
                            </td>

                            <td className="protocol-badge">

                              {String(
                                port.protocol ||
                                  ""
                              ).toUpperCase()}

                            </td>

                            <td>

                              <span className="state-badge">

                                <span></span>

                                {
                                  port.state
                                }

                              </span>

                            </td>

                            <td className="service-name">

                              {port.service ||
                                "Unknown"}

                            </td>

                            <td>

                              <span
                                className={`risk-badge ${risk.toLowerCase()}`}
                              >
                                {risk}
                              </span>

                            </td>

                          </tr>
                        );
                      }
                    )}

                  </tbody>

                </table>

              ) : (

                <div className="empty-state">
                  No matching ports found.
                </div>

              )}

            </div>

          </section>
        )}

        {/* =================================================
            SECURITY ANALYSIS
        ================================================= */}

        {scannedTarget &&
          settings.showRiskAnalysis && (
            <section className="analytics-grid">

              {/* RISK SUMMARY */}

              <div className="analytics-card">

                <div className="analytics-header">

                  <div>

                    <span className="eyebrow">
                      SECURITY ASSESSMENT
                    </span>

                    <h2>
                      Risk Analysis
                    </h2>

                  </div>

                </div>

                <div className="security-summary">

                  <div className="summary-row">

                    <span>
                      High Risk
                    </span>

                    <strong className="risk-high">
                      {riskSummary.high}
                    </strong>

                  </div>

                  <div className="summary-row">

                    <span>
                      Medium Risk
                    </span>

                    <strong className="risk-medium">
                      {riskSummary.medium}
                    </strong>

                  </div>

                  <div className="summary-row">

                    <span>
                      Low Risk
                    </span>

                    <strong className="risk-low">
                      {riskSummary.low}
                    </strong>

                  </div>

                  <div className="summary-row">

                    <span>
                      Informational
                    </span>

                    <strong className="risk-info">
                      {riskSummary.info}
                    </strong>

                  </div>

                </div>

              </div>

              {/* OVERALL ASSESSMENT */}

              <div className="analytics-card">

                <div className="analytics-header">

                  <div>

                    <span className="eyebrow">
                      SECURITY STATUS
                    </span>

                    <h2>
                      Overall Assessment
                    </h2>

                  </div>

                </div>

                <div className="overall-risk">

                  {riskSummary.high >
                  0 ? (

                    <>

                      <div className="risk-icon high">
                        !
                      </div>

                      <h3>
                        High Risk Detected
                      </h3>

                      <p>
                        One or more potentially
                        sensitive ports were detected.
                      </p>

                    </>

                  ) : riskSummary.medium >
                    0 ? (

                    <>

                      <div className="risk-icon medium">
                        !
                      </div>

                      <h3>
                        Review Recommended
                      </h3>

                      <p>
                        Some services should be
                        reviewed to ensure they are
                        intentionally exposed.
                      </p>

                    </>

                  ) : (

                    <>

                      <div className="risk-icon low">
                        ✓
                      </div>

                      <h3>
                        No High Risk Ports Detected
                      </h3>

                      <p>
                        No ports from the high-risk
                        list were found.
                      </p>

                    </>

                  )}

                </div>

              </div>

              {/* DETAILED FINDINGS */}

              <div className="analytics-card security-findings-card">

                <div className="analytics-header">

                  <div>

                    <span className="eyebrow">
                      SECURITY FINDINGS
                    </span>

                    <h2>
                      Detailed Findings
                    </h2>

                  </div>

                </div>

                <div className="security-findings">

                  {ports.filter(
                    (port) => {
                      const risk =
                        getRiskLevel(
                          port
                        );

                      return (
                        risk ===
                          "HIGH" ||
                        risk ===
                          "MEDIUM"
                      );
                    }
                  ).length ===
                  0 ? (

                    <div className="no-findings">

                      <div className="risk-icon low">
                        ✓
                      </div>

                      <h3>
                        No Significant Findings
                      </h3>

                      <p>
                        No high or medium-risk ports were
                        detected during this scan.
                      </p>

                    </div>

                  ) : (

                    ports
                      .filter(
                        (port) => {
                          const risk =
                            getRiskLevel(
                              port
                            );

                          return (
                            risk ===
                              "HIGH" ||
                            risk ===
                              "MEDIUM"
                          );
                        }
                      )
                      .map(
                        (port) => {

                          const risk =
                            getRiskLevel(
                              port
                            );

                          return (

                            <div
                              className={`security-finding ${risk.toLowerCase()}`}
                              key={`finding-${port.port}-${port.protocol}`}
                            >

                              <div className="finding-header">

                                <div>

                                  <span
                                    className={`risk-badge ${risk.toLowerCase()}`}
                                  >
                                    {risk}
                                  </span>

                                  <strong>
                                    Port{" "}
                                    {
                                      port.port
                                    }
                                  </strong>

                                </div>

                                <span className="finding-service">

                                  {port.service ||
                                    "Unknown Service"}

                                </span>

                              </div>

                              <p className="finding-reason">

                                {port.risk_reason ||
                                  "This service should be reviewed to ensure it is intentionally exposed."}

                              </p>

                              <div className="finding-recommendation">

                                <strong>
                                  Recommendation
                                </strong>

                                <p>

                                  {risk ===
                                  "HIGH"
                                    ? "Restrict or disable this service if it is not required. Use firewall rules and access controls to limit exposure."
                                    : "Review this service and ensure it is intentionally exposed. Restrict access where possible."}

                                </p>

                              </div>

                            </div>

                          );
                        }
                      )

                  )}

                </div>

              </div>

            </section>
          )}

        {/* =================================================
            SCAN HISTORY
        ================================================= */}

        {settings.showScanHistory && (

          <section className="history-section">

            <div className="history-header">

              <div>

                <span className="eyebrow">
                  ACTIVITY LOG
                </span>

                <h2>
                  Scan History
                </h2>

              </div>

              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "10px",
                }}
              >
                <select
                  value={selectedHistoryTarget}
                  onChange={(e) => {
                    setSelectedHistoryTarget(e.target.value);
                    setSelectedHistory(null);
                  }}
                  style={{
                    marginRight: "10px",
                    padding: "8px 12px",
                    background: "#111827",
                    color: "#ffffff",
                    border: "1px solid #334155",
                    borderRadius: "6px",
                    minWidth: "160px",
                  }}
                >
                  {historyTargets.map((historyTarget) => (
                    <option
                      key={historyTarget}
                      value={historyTarget}
                    >
                      {historyTarget === "ALL"
                        ? "All Targets"
                        : historyTarget}
                    </option>
                  ))}
                </select>

                <span className="history-count">
                  {filteredHistory.length} Saved
                </span>

                {history.length > 0 && (
                  <button
                    onClick={clearHistory}
                    style={{
                      marginLeft: "10px",
                      padding: "6px 10px",
                      border: "1px solid #7f1d1d",
                      borderRadius: "5px",
                      background: "#2a1014",
                      color: "#fca5a5",
                      cursor: "pointer",
                      fontSize: "10px",
                    }}
                  >
                    Clear
                  </button>
                )}
              </div>

            </div>

            {filteredHistory.length ===
            0 ? (

              <div className="history-empty">

                <span>
                  ◷
                </span>

                <p>
                  No previous scans yet.
                  Start a scan to create history.
                </p>

              </div>

            ) : (

              filteredHistory.map(
                (item) => (

                  <div
                    className="history-item"
                    key={item.id}
                  >

                    {/* HISTORY ICON */}

                    <div className="history-icon">
                      ◉
                    </div>

                    {/* TARGET + DATE */}

                    <div className="history-target">

                      <strong>
                        {item.target}
                      </strong>

                      <span>
                        {item.timestamp}
                      </span>

                    </div>

                    {/* OPEN PORTS */}

                    <div className="history-ports">

                      <strong>
                        {
                          item.security
                            ?.total_open_ports ||
                          item.ports
                            ?.length ||
                          0
                        }
                      </strong>

                      <span>
                        Open Ports
                      </span>

                    </div>

                    {/* RISK */}

                    <div className="history-risk">

                      <span className="history-risk-high">
                        High:{" "}
                        {
                          item.security
                            ?.high ||
                          0
                        }
                      </span>

                      <span className="history-risk-medium">
                        Medium:{" "}
                        {
                          item.security
                            ?.medium ||
                          0
                        }
                      </span>

                      <span className="history-risk-low">
                        Low:{" "}
                        {
                          item.security
                            ?.low ||
                          0
                        }
                      </span>

                    </div>

                    {/* SCAN TYPE */}

                    <div className="history-scan-type">

                      <span>
                        {
                          item.scan_type ||
                          "Full TCP"
                        }
                      </span>

                      <small>
                        {
                          item.scan_duration ||
                          0
                        }{" "}
                        sec
                      </small>

                    </div>

                    {/* STATUS + DELETE */}

                    <div className="history-actions">

                      <span className="history-status">
                        COMPLETED
                      </span>

                      <button
                        className="history-delete-button"
                        onClick={(
                          e
                        ) => {

                          e.stopPropagation();

                          if (
                            window.confirm(
                              `Delete scan history for ${item.target}?`
                            )
                          ) {

                            deleteHistoryScan(
                              item.id
                            );

                          }

                        }}
                      >
                        Delete
                      </button>

                    </div>

                    {/* VIEW */}

                    <button
                      className="history-view-button"
                      onClick={(
                        e
                      ) => {

                        e.stopPropagation();

                        loadHistoryScan(
                          item
                        );

                      }}
                    >
                      VIEW SCAN
                    </button>

                  </div>

                )
              )

            )}

          </section>

        )}

        {/* =================================================
            SELECTED HISTORY DETAILS
        ================================================= */}

        {selectedHistory && (

          <section className="history-details-panel">

            <div className="history-details-header">

              <div>

                <span className="eyebrow">
                  HISTORICAL SCAN
                </span>

                <h2>
                  Scan Details
                </h2>

              </div>

              <button
                className="history-close-button"
                onClick={() => {
                  setSelectedHistory(
                    null
                  );

                  setSearchTerm("");
                }}
              >
                ✕ Close
              </button>

            </div>

            {/* SUMMARY */}

            <div className="history-summary-grid">

              <div className="history-summary-card">

                <span>
                  TARGET
                </span>

                <strong>
                  {
                    selectedHistory.target
                  }
                </strong>

              </div>

              <div className="history-summary-card">

                <span>
                  SCAN TYPE
                </span>

                <strong>
                  {
                    selectedHistory.scan_type ||
                    "Full TCP"
                  }
                </strong>

              </div>

              <div className="history-summary-card">

                <span>
                  DURATION
                </span>

                <strong>
                  {
                    selectedHistory.scan_duration ||
                    0
                  }{" "}
                  sec
                </strong>

              </div>

              <div className="history-summary-card">

                <span>
                  OPEN PORTS
                </span>

                <strong>
                  {
                    selectedHistory
                      .ports
                      ?.length ||
                    selectedHistory
                      .security
                      ?.total_open_ports ||
                    0
                  }
                </strong>

              </div>

            </div>

            {/* RISK SUMMARY */}

            <div className="history-risk-summary">

              <div>

                <span>
                  HIGH
                </span>

                <strong className="history-risk-high">
                  {
                    selectedHistory
                      .security
                      ?.high ||
                    0
                  }
                </strong>

              </div>

              <div>

                <span>
                  MEDIUM
                </span>

                <strong className="history-risk-medium">
                  {
                    selectedHistory
                      .security
                      ?.medium ||
                    0
                  }
                </strong>

              </div>

              <div>

                <span>
                  LOW
                </span>

                <strong className="history-risk-low">
                  {
                    selectedHistory
                      .security
                      ?.low ||
                    0
                  }
                </strong>

              </div>

              <div>

                <span>
                  OVERALL RISK
                </span>

                <strong
                  className={`history-detail-risk ${
                    selectedHistory
                      .security
                      ?.risk_level
                      ?.toLowerCase() ||
                    "low"
                  }`}
                >
                  {
                    selectedHistory
                      .security
                      ?.risk_level ||
                    "LOW"
                  }
                </strong>

              </div>

            </div>

            {/* PORT TABLE */}

            <div className="history-detail-table">

              <div className="history-detail-table-header">

                <span className="eyebrow">
                  SCAN OUTPUT
                </span>

                <h3>
                  Detected Open Ports
                </h3>

              </div>

              {
                selectedHistory
                  .ports
                  ?.length > 0 ? (

                <div className="table-container">

                  <table>

                    <thead>

                      <tr>

                        <th>
                          PORT
                        </th>

                        <th>
                          PROTOCOL
                        </th>

                        <th>
                          STATE
                        </th>

                        <th>
                          SERVICE
                        </th>

                        <th>
                          RISK
                        </th>

                      </tr>

                    </thead>

                    <tbody>

                      {
                        selectedHistory
                          .ports
                          .map(
                            (port) => {

                              const risk =
                                getRiskLevel(
                                  port
                                );

                              return (

                                <tr
                                  key={`history-${port.port}-${port.protocol}`}
                                >

                                  <td className="port-number">
                                    {
                                      port.port
                                    }
                                  </td>

                                  <td className="protocol-badge">

                                    {String(
                                      port.protocol ||
                                        ""
                                    ).toUpperCase()}

                                  </td>

                                  <td>

                                    <span className="state-badge">

                                      <span></span>

                                      {
                                        port.state
                                      }

                                    </span>

                                  </td>

                                  <td className="service-name">

                                    {
                                      port.service ||
                                      "Unknown"
                                    }

                                  </td>

                                  <td>

                                    <span
                                      className={`risk-badge ${risk.toLowerCase()}`}
                                    >
                                      {
                                        risk
                                      }
                                    </span>

                                  </td>

                                </tr>

                              );
                            }
                          )
                      }

                    </tbody>

                  </table>

                </div>

              ) : (

                <div className="history-empty">

                  <p>
                    No port information is available for this scan.
                  </p>

                </div>

              )}

            </div>

          </section>

        )}

        {/* =================================================
            SETTINGS
        ================================================= */}

        <section className="settings-section">

          <div className="settings-header">

            <div>

              <span className="eyebrow">
                CONFIGURATION
              </span>

              <h2>
                Scanner Settings
              </h2>

              <p>
                Configure how the security scanner behaves.
              </p>

            </div>

          </div>

          {/* SCAN TYPE */}

          <div className="setting-row">

            <div className="setting-info">

              <strong>
                Scan Type
              </strong>

              <span>
                Select the network scanning method.
              </span>

            </div>

            <select
              className="form-select"
              value={settings.scanType}
              onChange={(e) => 
                updateSetting("scanType", e.target.value)}
            >
              <option value="Full TCP">Full TCP</option>
              <option value="Quick TCP">Quick TCP</option>
              <option value="UDP">UDP</option>
              <option value="Aggressive">Aggressive</option>
              <option value="Custom Ports">Custom Ports</option>
              <option value="Verbosity Scan">Verbosity Scan</option>
            </select>

            {settings.scanType === "Verbosity Scan" && (
              <div className="mt-3">

                <label className="form-label fw-bold">
                  Nmap Timing
                </label>

                <select
                  className="form-select"
                  value={verbosityTiming}
                  onChange={(e) =>
                    setVerbosityTiming(e.target.value)
                  }
                >
                  <option value="T0">T0</option>
                  <option value="T1">T1</option>
                  <option value="T2">T2</option>
                  <option value="T3">T3</option>
                  <option value="T4">T4</option>
                  <option value="T5">T5</option>
                </select>

                <div className="form-text">
                  Select the Nmap timing template from T0 to T5.
                </div>

              </div>
            )}

            {settings.scanType === "Custom Ports" && (
              <div className="setting-item">
                <label>Custom Ports</label>

                <input
                  type="text"
                  value={settings.customPorts || ""}
                  onChange={(e) =>
                    updateSetting("customPorts", e.target.value)
                  }
                  placeholder="80, 443, 3306 or 20-25"
                />

                <button
                  type="button"
                  onClick={() => {
                    localStorage.setItem(
                      "portScannerSettings",
                      JSON.stringify(settings)
                    );
                    setError("");
                    alert("Custom ports saved successfully.");
                  }}
                >
                  Save
                </button>

                <small>
                  Enter ports separated by commas or port ranges.
                </small>
              </div>
            )}

          </div>

          {/* AUTO SAVE */}

          <div className="setting-row">

            <div className="setting-info">

              <strong>
                Auto Save History
              </strong>

              <span>
                Automatically save completed scans.
              </span>

            </div>

            <label className="toggle">

              <input
                type="checkbox"
                checked={
                  settings.autoSaveHistory
                }
                onChange={(e) =>
                  updateSetting(
                    "autoSaveHistory",
                    e.target.checked
                  )
                }
              />

              <span className="toggle-slider"></span>

            </label>

          </div>

          {/* RISK ANALYSIS */}

          <div className="setting-row">

            <div className="setting-info">

              <strong>
                Security Risk Analysis
              </strong>

              <span>
                Display port risk classification and analysis.
              </span>

            </div>

            <label className="toggle">

              <input
                type="checkbox"
                checked={
                  settings.showRiskAnalysis
                }
                onChange={(e) =>
                  updateSetting(
                    "showRiskAnalysis",
                    e.target.checked
                  )
                }
              />

              <span className="toggle-slider"></span>

            </label>

          </div>

          {/* SCAN HISTORY */}

          <div className="setting-row">

            <div className="setting-info">

              <strong>
                Scan History
              </strong>

              <span>
                Display previously completed scans.
              </span>

            </div>

            <label className="toggle">

              <input
                type="checkbox"
                checked={
                  settings.showScanHistory
                }
                onChange={(e) =>
                  updateSetting(
                    "showScanHistory",
                    e.target.checked
                  )
                }
              />

              <span className="toggle-slider"></span>

            </label>

          </div>

        </section>

        {/* =================================================
            WELCOME SCREEN
        ================================================= */}

        {!scannedTarget &&
          history.length === 0 && (

            <section className="welcome-card">

              <div className="shield">
                🛡️
              </div>

              <h2>
                Advanced Network Security
              </h2>

              <p>
                Perform comprehensive network scans 
                using Nmap and analyze the services and 
                security risks exposed by a target system.
              </p>

              <div className="security-features">

                <div>

                  <strong>
                    NMAP
                  </strong>

                  <span>
                    Powerful scanning engine
                  </span>

                </div>

                <div>

                  <strong>
                    MULTI-SCAN
                  </strong>

                  <span>
                    TCP • UDP • Custom • Aggressive • Verbosity
                  </span>

                </div>

                <div>

                  <strong>
                    SECURITY
                  </strong>

                  <span>
                    Risk analysis
                  </span>

                </div>

              </div>

            </section>

          )}

      </main>

    </div>
  );
}

export default App;