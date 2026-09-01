let incidentChart = null;


/* ==========================================
   LOAD SYSTEM STATUS
========================================== */


async function loadStatus() {

    try {

        const res = await fetch("/api/status?_" + Date.now(), {
            cache: "no-store"
        });

        if (!res.ok) {
            throw new Error("Status API failed");
        }

        const data = await res.json();
        const statistics = data.statistics || {};

        const total = Number(statistics.total_incidents || 0);
        const critical = Number(statistics.critical || 0);
        const high = Number(statistics.high || 0);
        const medium = Number(statistics.medium || 0);
        const low = Number(statistics.low || 0);

        const open = Number(statistics.open || 0);
        const investigating = Number(statistics.investigating || 0);
        const contained = Number(statistics.contained || 0);
        const closed = Number(statistics.closed || 0);
        const quarantined = Number(statistics.quarantined || 0);


        /* ================================
           EXISTING DASHBOARD COUNTERS
        ================================= */

        const healthEl = document.getElementById("health");
        const riskEl = document.getElementById("risk");
        const quarantineEl = document.getElementById("quarantine");
        const incidentsEl = document.getElementById("incidents");

        if (healthEl) healthEl.innerText = "100%";
        if (riskEl) riskEl.innerText = critical;
        if (quarantineEl) quarantineEl.innerText = quarantined;


        /*
         * IMPORTANT:
         * #incidents is also used by the incident container
         * in the current HTML, so don't overwrite it here.
         */


        /* ================================
           OVERALL CIRCLE CENTER
        ================================= */

        const circle = document.getElementById("overallCircle");
        const totalEl = document.getElementById("overallTotal");

        if (totalEl) {
            totalEl.textContent = String(total);
        }


        /* ================================
           SEVERITY LEGEND COUNTS
        ================================= */

        const criticalEl =
            document.getElementById("overallCritical");

        const highEl =
            document.getElementById("overallHigh");

        const mediumEl =
            document.getElementById("overallMedium");

        const lowEl =
            document.getElementById("overallLow");


        if (criticalEl)
            criticalEl.textContent = String(critical);

        if (highEl)
            highEl.textContent = String(high);

        if (mediumEl)
            mediumEl.textContent = String(medium);

        if (lowEl)
            lowEl.textContent = String(low);


        /* ================================
           CIRCLE GRAPH
        ================================= */

        if (circle) {

            if (total === 0) {

                circle.style.background = "#334155";

            } else {

                const criticalDeg =
                    (critical / total) * 360;

                const highDeg =
                    (high / total) * 360;

                const mediumDeg =
                    (medium / total) * 360;

                const lowDeg =
                    (low / total) * 360;


                const p1 = criticalDeg;
                const p2 = p1 + highDeg;
                const p3 = p2 + mediumDeg;
                const p4 = p3 + lowDeg;


                circle.style.background =
                    "conic-gradient(" +
                    "#ef4444 0deg " + p1 + "deg," +
                    "#f97316 " + p1 + "deg " + p2 + "deg," +
                    "#eab308 " + p2 + "deg " + p3 + "deg," +
                    "#22c55e " + p3 + "deg " + p4 + "deg" +
                    ")";

            }

        }


        console.log("RDRS STATUS:", {
            total,
            critical,
            high,
            medium,
            low,
            open,
            investigating,
            contained,
            closed,
            quarantined
        });


    } catch (error) {

        console.error(
            "❌ RDRS Status Error:",
            error
        );

    }

}


async function loadIncidents() {

    try {

        const res = await fetch(
            "/api/incidents?_" + Date.now(),
            {
                cache: "no-store"
            }
        );

        if (!res.ok) {
            throw new Error("Incident API failed");
        }

        const data = await res.json();

        console.log("RDRS INCIDENT DATA:", data);


        const container =
            document.getElementById("incidents");


        if (!container) {
            console.error(
                "❌ incidents container not found"
            );
            return;
        }


        if (!Array.isArray(data) || data.length === 0) {

            container.innerHTML = `
                <div style="
                    padding:25px;
                    text-align:center;
                    color:#94a3b8;
                    background:#0f172a;
                    border:1px solid #334155;
                    border-radius:10px;
                ">
                    ✅ No security incidents found.
                </div>
            `;

            return;
        }


        let html = "";


        data.forEach(function(i) {

            const level =
                String(i.risk_level || i.severity || "UNKNOWN")
                .toUpperCase();

            const status =
                String(i.status || "OPEN")
                .toUpperCase();


            const file =
                i.file || {};

            const filename =
                file.name || "Unknown file";


            let severityColor = "#64748b";
            let severityIcon = "⚪";


            if (level === "CRITICAL") {

                severityColor = "#ef4444";
                severityIcon = "🔴";

            }
            else if (level === "HIGH") {

                severityColor = "#f97316";
                severityIcon = "🟠";

            }
            else if (level === "MEDIUM") {

                severityColor = "#eab308";
                severityIcon = "🟡";

            }
            else if (level === "LOW") {

                severityColor = "#22c55e";
                severityIcon = "🟢";

            }


            html += `

            <div style="
                background:#0f172a;
                border:1px solid #334155;
                border-left:5px solid ${severityColor};
                border-radius:10px;
                padding:18px;
                margin:12px 0;
                box-shadow:0 5px 18px rgba(0,0,0,.25);
            ">

                <div style="
                    display:flex;
                    justify-content:space-between;
                    align-items:center;
                    gap:15px;
                    flex-wrap:wrap;
                ">

                    <div>

                        <div style="
                            font-size:16px;
                            font-weight:800;
                            color:white;
                        ">
                            ${severityIcon}
                            ${escapeHtml(
                                i.incident_id || "Unknown Incident"
                            )}
                        </div>


                        <div style="
                            margin-top:7px;
                            color:#cbd5e1;
                            font-size:14px;
                            font-weight:600;
                        ">
                            📄 ${escapeHtml(filename)}
                        </div>

                    </div>


                    <div style="
                        display:flex;
                        gap:8px;
                        align-items:center;
                        flex-wrap:wrap;
                    ">

                        <span style="
                            padding:6px 10px;
                            border-radius:999px;
                            background:${severityColor};
                            color:white;
                            font-weight:800;
                            font-size:12px;
                        ">
                            ${level}
                        </span>


                        <span style="
                            padding:6px 10px;
                            border-radius:999px;
                            background:#1e293b;
                            color:#cbd5e1;
                            font-weight:700;
                            font-size:12px;
                        ">
                            ${status}
                        </span>

                    </div>

                </div>


                <div style="
                    margin-top:15px;
                    display:flex;
                    justify-content:space-between;
                    align-items:center;
                    gap:10px;
                    flex-wrap:wrap;
                ">

                    <div style="
                        color:#94a3b8;
                        font-size:13px;
                    ">
                        Risk Score:
                        <strong style="color:white;">
                            ${Number(i.risk_score || 0)}/100
                        </strong>
                    </div>


                    <button
                        onclick="viewDetailsById('${escapeHtml(i.incident_id || "")}')" 
                        style="
                            background:#2563eb;
                            color:white;
                            border:none;
                            padding:9px 15px;
                            border-radius:7px;
                            cursor:pointer;
                            font-weight:800;
                        "
                    >
                        🔎 VIEW DETAILS
                    </button>

                </div>

            </div>

            `;

        });


        container.innerHTML = html;


        updateIncidentChart(data);


    } catch (error) {

        console.error(
            "❌ Incident loading error:",
            error
        );

    }

}


/* ==========================================
   VIEW INCIDENT DETAILS
========================================== */

function viewDetails(incident) {

    const modal =
        document.getElementById("detailsModal");

    const content =
        document.getElementById("detailsContent");


    if (!modal || !content) {

        console.error(
            "❌ Details modal not found"
        );

        return;
    }


    const file =
        incident.file || {};

    const response =
        incident.response || {};

    const analysis =
        incident.analysis || {};

    const originalPath =
        response.original_path ||
        file.original_path ||
        file.path ||
        "N/A";

    const quarantinePath =
        response.quarantine_path ||
        response.current_quarantine_path ||
        "Not quarantined";

    const fileSize =
        file.size !== undefined && file.size !== null
            ? file.size
            : "N/A";

    const entropy =
        analysis.entropy !== undefined &&
        analysis.entropy !== null
            ? analysis.entropy
            : "N/A";

    const suspicious =
        analysis.suspicious === true
            ? "YES"
            : analysis.suspicious === false
                ? "NO"
                : "N/A";

    const responseStatus =
        response.status ||
        "N/A";


    const reasons =
        Array.isArray(incident.risk_reasons)
            ? incident.risk_reasons
            : [];


    const reasonHtml =
        reasons.length
            ? reasons.map(function(reason) {

                return `
                    <li style="
                        margin:7px 0;
                        color:#cbd5e1;
                    ">
                        ⚠️ ${escapeHtml(String(reason))}
                    </li>
                `;

              }).join("")

            : `
                <li style="color:#94a3b8;">
                    No suspicious indicators recorded
                </li>
            `;


    content.innerHTML = `

        <div class="rdrs-detail-grid">


            <!-- INCIDENT ID -->

            <div class="detail-box">

                <strong>🆔 Incident ID</strong>

                <div class="detail-value">
                    ${escapeHtml(
                        incident.incident_id || "N/A"
                    )}
                </div>

            </div>


            <!-- FILE -->

            <div class="detail-box">

                <strong>📄 File Name</strong>

                <div class="detail-value">
                    ${escapeHtml(
                        file.name || "N/A"
                    )}
                </div>

            </div>


            <!-- ORIGINAL LOCATION -->

            <div class="detail-box">

                <strong>📁 Original Location</strong>

                <div class="detail-value" style="
                    word-break:break-all;
                ">
                    ${escapeHtml(
                        originalPath
                    )}
                </div>

            </div>


            <!-- QUARANTINE LOCATION -->

            <div class="detail-box">

                <strong>🛡️ Quarantine Location</strong>

                <div class="detail-value" style="
                    word-break:break-all;
                ">
                    ${escapeHtml(
                        quarantinePath
                    )}
                </div>

            </div>


            <!-- SIZE -->

            <div class="detail-box">

                <strong>📦 File Size</strong>

                <div class="detail-value">
                    ${fileSize}
                    bytes
                </div>

            </div>


            <!-- SHA256 -->

            <div class="detail-box">

                <strong>🔐 SHA-256</strong>

                <div class="detail-value" style="
                    word-break:break-all;
                    font-family:monospace;
                    font-size:12px;
                ">
                    ${escapeHtml(
                        file.sha256 || "N/A"
                    )}
                </div>

            </div>


            <!-- ENTROPY -->

            <div class="detail-box">

                <strong>📊 Entropy</strong>

                <div class="detail-value">
                    ${entropy}
                </div>

            </div>


            <!-- RISK SCORE -->

            <div class="detail-box">

                <strong>🎯 Risk Score</strong>

                <div class="detail-value">
                    ${Number(
                        incident.risk_score || 0
                    )}/100
                </div>

            </div>


            <!-- RISK LEVEL -->

            <div class="detail-box">

                <strong>🚨 Risk Level</strong>

                <div class="detail-value">
                    ${escapeHtml(
                        incident.risk_level ||
                        incident.severity ||
                        "N/A"
                    )}
                </div>

            </div>


            <!-- SUSPICIOUS -->

            <div class="detail-box">

                <strong>🔎 Suspicious</strong>

                <div class="detail-value">
                    ${
                        suspicious
                    }
                </div>

            </div>


            <!-- STATUS -->

            <div class="detail-box">

                <strong>📌 Status</strong>

                <div class="detail-value">
                    ${escapeHtml(
                        incident.status || "OPEN"
                    )}
                </div>

            </div>


            <!-- EVENT -->

            <div class="detail-box">

                <strong>⚡ Event</strong>

                <div class="detail-value">
                    ${escapeHtml(
                        incident.event_type || "N/A"
                    )}
                </div>

            </div>


            <!-- TIMESTAMP -->

            <div class="detail-box">

                <strong>🕒 Timestamp</strong>

                <div class="detail-value">
                    ${escapeHtml(
                        incident.timestamp || "N/A"
                    )}
                </div>

            </div>


            <!-- RESPONSE -->

            <div class="detail-box">

                <strong>🛡️ Response</strong>

                <div class="detail-value">
                    ${escapeHtml(
                        responseStatus
                    )}
                </div>

            </div>


            <!-- RISK REASONS -->

            <div class="detail-box">

                <strong>📝 Risk Reasons</strong>

                <ul style="
                    margin-top:10px;
                    padding-left:22px;
                ">
                    ${reasonHtml}
                </ul>

            </div>


            <!-- STATUS ACTIONS -->

            <div style="
                margin-top:10px;
                display:flex;
                gap:10px;
                flex-wrap:wrap;
            ">

                ${
                    String(incident.status || "DETECTED").toUpperCase() === "DETECTED"
                    ? `
                        <button
                            onclick="changeIncidentStatus('${incident.incident_id}','INVESTIGATING')"
                            style="
                                background:#7c3aed;
                                color:white;
                                border:none;
                                padding:10px 14px;
                                border-radius:7px;
                                cursor:pointer;
                                font-weight:700;
                            "
                        >
                            🔎 INVESTIGATING
                        </button>
                    `
                    : ""
                }

                ${
                    String(incident.status || "").toUpperCase() === "INVESTIGATING"
                    ? `
                        <button
                            onclick="changeIncidentStatus('${incident.incident_id}','CONTAINED')"
                            style="
                                background:#ea580c;
                                color:white;
                                border:none;
                                padding:10px 14px;
                                border-radius:7px;
                                cursor:pointer;
                                font-weight:700;
                            "
                        >
                            🛡️ CONTAINED
                        </button>
                    `
                    : ""
                }

                ${
                    String(incident.status || "").toUpperCase() === "CONTAINED"
                    ? `
                        <button
                            onclick="changeIncidentStatus('${incident.incident_id}','CLOSED')"
                            style="
                                background:#16a34a;
                                color:white;
                                border:none;
                                padding:10px 14px;
                                border-radius:7px;
                                cursor:pointer;
                                font-weight:700;
                            "
                        >
                            ✅ CLOSED
                        </button>
                    `
                    : ""
                }

                ${
                    String(incident.status || "").toUpperCase() === "CLOSED"
                    ? `
                        <span style="
                            display:inline-flex;
                            align-items:center;
                            padding:10px 14px;
                            border-radius:7px;
                            background:#374151;
                            color:#d1d5db;
                            font-weight:700;
                        ">
                            🔒 INCIDENT CLOSED
                        </span>
                    `
                    : ""
                }

            </div>

        </div>

    `;


    modal.classList.add("show");
    modal.style.display = "flex";

}


function closeDetails() {

    const modal =
        document.getElementById("detailsModal");

    if (modal) {
        modal.classList.remove("show");
        modal.style.display = "none";
    }

}


/* ==========================================
   INCIDENT DONUT GRAPH
========================================== */

function updateIncidentChart(incidents) {

    const canvas = document.getElementById("incidentChart");

    if (!canvas) {
        console.error("incidentChart canvas not found");
        return;
    }

    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;

    incidents.forEach(function(incident) {

        const level =
            String(incident.risk_level || "").toUpperCase();

        if (level === "CRITICAL") {
            critical++;
        } else if (level === "HIGH") {
            high++;
        } else if (level === "MEDIUM") {
            medium++;
        } else if (level === "LOW") {
            low++;
        }

    });

    const graphCritical =
        document.getElementById("graphCritical");

    const graphHigh =
        document.getElementById("graphHigh");

    const graphMedium =
        document.getElementById("graphMedium");

    const graphLow =
        document.getElementById("graphLow");

    if (graphCritical)
        graphCritical.textContent = critical;

    if (graphHigh)
        graphHigh.textContent = high;

    if (graphMedium)
        graphMedium.textContent = medium;

    if (graphLow)
        graphLow.textContent = low;


    if (incidentChart) {
        incidentChart.destroy();
        incidentChart = null;
    }


    incidentChart = new Chart(canvas, {

        type: "bar",

        data: {

            labels: [
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW"
            ],

            datasets: [{

                label: "Incidents",

                data: [
                    critical,
                    high,
                    medium,
                    low
                ],

                backgroundColor: [
                    "#ef4444",
                    "#f97316",
                    "#eab308",
                    "#22c55e"
                ],

                borderRadius: 8,

                borderWidth: 0,

                maxBarThickness: 75

            }]

        },

        options: {

            responsive: true,

            maintainAspectRatio: false,

            animation: {
                duration: 500
            },

            scales: {

                y: {

                    beginAtZero: true,

                    ticks: {
                        precision: 0,
                        color: "#94a3b8"
                    },

                    grid: {
                        color: "rgba(148,163,184,.12)"
                    }

                },

                x: {

                    ticks: {
                        color: "#cbd5e1",
                        font: {
                            weight: "bold"
                        }
                    },

                    grid: {
                        display: false
                    }

                }

            },

            plugins: {

                legend: {
                    display: false
                },

                tooltip: {

                    callbacks: {

                        label: function(context) {
                            return " Incidents: " + context.raw;
                        }

                    }

                }

            }

        }

    });

}


/* ==========================================
   REFRESH DASHBOARD
========================================== */

async function refresh() {

    await loadStatus();

    await loadIncidents();

}


/* INITIAL LOAD */

refresh();


/* AUTO REFRESH EVERY 5 SECONDS */

setInterval(refresh, 5000);


/* =====================================================
   RDRS BUTTON FIX
   Refresh Incidents
===================================================== */

document.addEventListener("DOMContentLoaded", function () {

    const refreshBtn =
        document.getElementById("refreshIncidentsBtn");

    if (!refreshBtn) {
        console.error("❌ Refresh Incidents button not found");
        return;
    }

    refreshBtn.addEventListener("click", async function (event) {

        event.preventDefault();
        event.stopPropagation();

        console.log("🔄 Refresh Incidents clicked");

        try {

            refreshBtn.disabled = true;
            refreshBtn.textContent = "🔄 REFRESHING...";

            await loadIncidents();

            console.log("✅ Incidents refreshed");

        } catch (error) {

            console.error(
                "❌ Refresh Incidents error:",
                error
            );

        } finally {

            refreshBtn.disabled = false;
            refreshBtn.textContent = "🔄 REFRESH INCIDENTS";

        }

    });

});



/* =====================================================
   RDRS VIEW DETAILS BY ID
===================================================== */

function viewDetailsById(incidentId) {

    console.log("🔎 View Details clicked:", incidentId);

    fetch("/api/incidents?_=" + Date.now(), {
        cache: "no-store"
    })
    .then(function (response) {

        if (!response.ok) {
            throw new Error("Failed to load incident");
        }

        return response.json();

    })
    .then(function (incidents) {

        const incident =
            incidents.find(function (item) {
                return item.incident_id === incidentId;
            });

        if (!incident) {

            console.error(
                "Incident not found:",
                incidentId
            );

            alert("Incident details not found.");
            return;
        }

        viewDetails(incident);

    })
    .catch(function (error) {

        console.error(
            "❌ View Details error:",
            error
        );

        alert(
            "Unable to load incident details."
        );

    });

}


/* ==========================================
   PHASE 8 — INCIDENT LIFECYCLE STATUS UPDATE
========================================== */

async function changeIncidentStatus(incidentId, newStatus) {

    try {

        const response = await fetch(
            `/api/incidents/${encodeURIComponent(incidentId)}/status?status=${encodeURIComponent(newStatus)}`,
            {
                method: "PUT",
                cache: "no-store"
            }
        );

        const data = await response.json();

        if (!response.ok || data.status === "error") {

            throw new Error(
                data.message || "Failed to update incident status"
            );

        }

        console.log(
            "✅ Incident status updated:",
            incidentId,
            "→",
            newStatus
        );

        alert(
            `✅ Incident ${incidentId} updated to ${newStatus}`
        );

        await loadIncidents();

        if (typeof loadStatus === "function") {
            await loadStatus();
        }

    } catch (error) {

        console.error(
            "❌ Incident status update failed:",
            error
        );

        alert(
            `❌ Status update failed:\n${error.message}`
        );
    }
}

