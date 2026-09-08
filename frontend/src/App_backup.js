import { useState } from "react";
import "./App.css";

function App() {
  const [target, setTarget] = useState("127.0.0.1");
  const [ports, setPorts] = useState([]);
  const [security, setSecurity] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [scannedTarget, setScannedTarget] = useState("");
  const [search, setSearch] = useState("");

  const handleScan = async () => {
    if (!target.trim()) {
      setError("Please enter a target.");
      return;
    }

    setLoading(true);
    setError("");
    setPorts([]);
    setSecurity(null);
    setScannedTarget("");

    try {
      const response = await fetch("http://127.0.0.1:5000/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          target: target.trim(),
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Scan failed.");
      }

      setPorts(data.ports || []);
      setSecurity(data.security || null);
      setScannedTarget(data.target || target.trim());
    } catch (err) {
      setError(
        err.message ||
          "Unable to connect to the backend. Make sure Flask is running on port 5000."
      );
    } finally {
      setLoading(false);
    }
  };

  const filteredPorts = ports.filter((port) => {
    const searchText = search.toLowerCase();

    return (
      String(port.port).includes(searchText) ||
      port.protocol.toLowerCase().includes(searchText) ||
      port.service.toLowerCase().includes(searchText)
    );
  });

  const getRiskClass = (risk) => {
    if (!risk) return "";

    return risk.toLowerCase();
  };

  return (
    <div className="app">

      {/* =====================================================
          SIDEBAR
      ===================================================== */}

      <aside className="sidebar">

        <div className="logo">
          <div className="logo-icon">🛡</div>

          <div>
            <h2>ADVANCED SECURITY</h2>
            <span>PORT SCANNER</span>
          </div>
        </div>

        <nav className="navigation">

          <button className="nav-item active">
            <span>◉</span>
            Scanner
          </button>

          <button className="nav-item">
            <span>▣</span>
            Security Analysis
          </button>

          <button className="nav-item">
            <span>◷</span>
            Scan History
          </button>

          <button className="nav-item">
            <span>⚙</span>
            Settings
          </button>

        </nav>

        <div className="sidebar-footer">

          <div className="backend-status">
            <span className="online-dot"></span>
            Backend Online
          </div>

          <small>
            Flask + Nmap
          </small>

        </div>

      </aside>


      {/* =====================================================
          MAIN CONTENT
      ===================================================== */}

      <main className="main-content">

        {/* TOP BAR */}

        <header className="topbar">

          <div>
            <span className="eyebrow">
              SECURITY OPERATIONS
            </span>

            <h1>
              Advanced Security Scanner
            </h1>

            <p>
              Discover open ports and identify potential security risks.
            </p>
          </div>

          <div className="connection-status">
            <span className="online-dot"></span>
            System Online
          </div>

        </header>


        {/* =================================================
            SCANNER
        ================================================= */}

        <section className="scanner-card">

          <div className="section-title">

            <div>
              <span className="eyebrow">
                NMAP SCANNER
              </span>

              <h2>
                Start a Security Scan
              </h2>
            </div>

            <span className="scan-type">
              FULL TCP SCAN
            </span>

          </div>


          <div className="scan-form">

            <div className="input-wrapper">

              <span className="input-icon">
                ⌕
              </span>

              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="Enter target e.g. 127.0.0.1"
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    handleScan();
                  }
                }}
              />

            </div>

            <button
              className="scan-button"
              onClick={handleScan}
              disabled={loading}
            >

              {loading ? (
                <>
                  <span className="spinner"></span>
                  Scanning...
                </>
              ) : (
                <>
                  Scan Target
                </>
              )}

            </button>

          </div>


          {error && (
            <div className="error-message">
              {error}
            </div>
          )}

        </section>


        {/* =================================================
            STATISTICS
        ================================================= */}

        {security && (

          <section className="stats-grid">

            <div className="stat-card">

              <div className="stat-icon blue">
                ◎
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
                ◉
              </div>

              <div>
                <span>
                  OPEN PORTS
                </span>

                <strong>
                  {security.total_open_ports}
                </strong>
              </div>

            </div>


            <div className="stat-card">

              <div className="stat-icon orange">
                ⚠
              </div>

              <div>
                <span>
                  HIGH RISK
                </span>

                <strong>
                  {security.high}
                </strong>
              </div>

            </div>


            <div className="stat-card">

              <div className="stat-icon purple">
                ◈
              </div>

              <div>
                <span>
                  OVERALL RISK
                </span>

                <strong className={`risk-${getRiskClass(security.risk_level)}`}>
                  {security.risk_level}
                </strong>
              </div>

            </div>

          </section>

        )}


        {/* =================================================
            SECURITY ANALYSIS
        ================================================= */}

        {security && (

          <section className="analytics-grid">

            {/* RISK SUMMARY */}

            <div className="analytics-card">

              <div className="analytics-header">

                <div>
                  <span className="eyebrow">
                    RISK BREAKDOWN
                  </span>

                  <h2>
                    Security Analysis
                  </h2>
                </div>

              </div>


              <div className="security-summary">

                <div className="summary-row">

                  <span>
                    High Risk Ports
                  </span>

                  <strong className="risk-high">
                    {security.high}
                  </strong>

                </div>


                <div className="summary-row">

                  <span>
                    Medium Risk Ports
                  </span>

                  <strong className="risk-medium">
                    {security.medium}
                  </strong>

                </div>


                <div className="summary-row">

                  <span>
                    Low Risk Ports
                  </span>

                  <strong className="risk-low">
                    {security.low}
                  </strong>

                </div>


                <div className="summary-row">

                  <span>
                    Total Open Ports
                  </span>

                  <strong className="risk-info">
                    {security.total_open_ports}
                  </strong>

                </div>

              </div>

            </div>


            {/* OVERALL RISK */}

            <div className="analytics-card">

              <div className="analytics-header">

                <div>
                  <span className="eyebrow">
                    SECURITY STATUS
                  </span>

                  <h2>
                    Overall Risk
                  </h2>
                </div>

              </div>


              <div className="overall-risk">

                <div
                  className={`risk-icon ${getRiskClass(
                    security.risk_level
                  )}`}
                >
                  ⚠
                </div>

                <h3>
                  {security.risk_level} RISK
                </h3>

                <p>
                  {security.risk_level === "HIGH"
                    ? "High-risk services were detected. Review the recommendations below."
                    : security.risk_level === "MEDIUM"
                    ? "Potentially exposed services were detected. Review the scan results."
                    : "No high-risk services were detected in this scan."}
                </p>

              </div>

            </div>

          </section>

        )}


        {/* =================================================
            RECOMMENDATIONS
        ================================================= */}

        {security &&
          security.recommendations &&
          security.recommendations.length > 0 && (

            <section className="history-section">

              <div className="history-header">

                <div>
                  <span className="eyebrow">
                    SECURITY ADVISORY
                  </span>

                  <h2>
                    Recommendations
                  </h2>
                </div>

                <span className="history-count">
                  {security.recommendations.length} Findings
                </span>

              </div>


              {security.recommendations.map(
                (recommendation, index) => (

                  <div
                    className="history-item"
                    key={`${recommendation.port}-${index}`}
                  >

                    <div
                      className="history-icon"
                    >
                      ⚠
                    </div>


                    <div className="history-target">

                      <strong>
                        Port {recommendation.port}
                      </strong>

                      <span>
                        {recommendation.message}
                      </span>

                    </div>


                    <div
                      className={`risk-badge ${getRiskClass(
                        recommendation.risk
                      )}`}
                    >
                      {recommendation.risk}
                    </div>

                  </div>

                )
              )}

            </section>

          )}


        {/* =================================================
            PORT RESULTS
        ================================================= */}

        {security && (

          <section className="results-section">

            <div className="results-header">

              <div>

                <span className="eyebrow">
                  NMAP RESULTS
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


              <span className="results-count">
                {ports.length} Open Ports
              </span>

            </div>


            {/* SEARCH */}

            <div className="table-toolbar">

              <div className="search-box">

                <span>
                  ⌕
                </span>

                <input
                  type="text"
                  placeholder="Search ports or services..."
                  value={search}
                  onChange={(e) =>
                    setSearch(e.target.value)
                  }
                />

              </div>

            </div>


            {/* TABLE */}

            <div className="table-container">

              {filteredPorts.length > 0 ? (

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

                    {filteredPorts.map((port) => {

                      const analyzedPort =
                        security
                          ? security.recommendations.find(
                              (item) =>
                                item.port === port.port
                            )
                          : null;

                      let risk = "LOW";

                      if (security) {

                        const analyzed =
                          security &&
                          security.total_open_ports
                            ? null
                            : null;

                        if (port.port === 445) {
                          risk = "HIGH";
                        } else if (port.port === 3306) {
                          risk = "HIGH";
                        } else if (port.port === 5000) {
                          risk = "MEDIUM";
                        } else if (port.port === 21) {
                          risk = "HIGH";
                        } else if (port.port === 23) {
                          risk = "HIGH";
                        } else if (port.port === 3389) {
                          risk = "HIGH";
                        } else if (port.port === 80) {
                          risk = "MEDIUM";
                        } else if (port.port === 22) {
                          risk = "MEDIUM";
                        }
                      }

                      return (

                        <tr
                          key={`${port.port}-${port.protocol}`}
                        >

                          <td className="port-number">
                            {port.port}
                          </td>

                          <td className="protocol-badge">
                            {port.protocol.toUpperCase()}
                          </td>

                          <td>

                            <span className="state-badge">

                              <span></span>

                              {port.state}

                            </span>

                          </td>

                          <td className="service-name">
                            {port.service}
                          </td>

                          <td>

                            <span
                              className={`risk-badge ${getRiskClass(
                                risk
                              )}`}
                            >
                              {risk}
                            </span>

                          </td>

                        </tr>

                      );

                    })}

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
            WELCOME SCREEN
        ================================================= */}

        {!security && !loading && !error && (

          <section className="welcome-card">

            <div className="shield">
              🛡
            </div>

            <h2>
              Ready to Scan
            </h2>

            <p>
              Enter an IP address, hostname, or authorized
              target above to perform a full TCP port scan
              and security analysis.
            </p>


            <div className="security-features">

              <div>

                <strong>
                  NMAP
                </strong>

                <span>
                  Port Discovery
                </span>

              </div>


              <div>

                <strong>
                  SERVICE
                </strong>

                <span>
                  Detection
                </span>

              </div>


              <div>

                <strong>
                  RISK
                </strong>

                <span>
                  Analysis
                </span>

              </div>

            </div>

          </section>

        )}


        {/* =================================================
            SCANNING STATE
        ================================================= */}

        {loading && (

          <section className="welcome-card">

            <div className="spinner"></div>

            <h2 style={{ marginTop: "18px" }}>
              Scanning Target...
            </h2>

            <p>
              Nmap is scanning the target and analyzing
              detected services. This may take a little while.
            </p>

          </section>

        )}

      </main>

    </div>
  );
}

export default App;