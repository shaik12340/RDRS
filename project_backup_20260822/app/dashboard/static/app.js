async function loadStatus(){

const res=await fetch("/api/status");
const data=await res.json();

document.getElementById("health").innerText="100%";
document.getElementById("risk").innerText=data.statistics.critical;
document.getElementById("quarantine").innerText=data.statistics.quarantined;
document.getElementById("incidents").innerText=data.statistics.total_incidents;

}

async function loadIncidents(){

const res=await fetch("/api/incidents");
const data=await res.json();

let html="";

if(data.length===0){

html="<tr><td colspan='3'>No Incidents</td></tr>";

}else{

data.forEach(function(i){

html+=`
<tr>
<td>${i.incident_id}</td>
<td>${i.risk_level}</td>
<td>${i.status}</td>
</tr>
`;

});

}

document.getElementById("incidentTable").innerHTML=html;

}

async function refresh(){

await loadStatus();
await loadIncidents();

}

refresh();

setInterval(refresh,5000);
