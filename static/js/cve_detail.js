document.addEventListener("DOMContentLoaded", function() {
    // Get CVE ID from the HTML element
    const cveId = document.getElementById("cve-id").textContent.trim();
    
    if (!cveId) {
        console.error("Invalid CVE ID");
        displayError("Invalid CVE ID. Please provide a valid CVE identifier.");
        return;
    }
    
    console.log("Fetching details for:", cveId);
    
    // Fetch CVE details from the API using POST method
    fetch(`/api/cves/${cveId}`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ cve_id: cveId })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`CVE not found: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        console.log("API Response:", data); // Log the response for debugging
        
        if (!data || !data.cve) {
            throw new Error("Invalid data returned from the API");
        }
        
        // Display CVE data
        displayCveDetails(data);
    })
    .catch(error => {
        console.error("Error processing CVE details:", error);
        displayError(`Could not load details for ${cveId}. The CVE might not exist or there was a problem with the request.`);
    });
});

// Function to display error message
function displayError(message) {
    document.querySelector('.cve-detail-container').innerHTML = `
        <div class="error-message">
            <h3>Error</h3>
            <p>${message}</p>
            <p><a href="/cves/list">Return to CVE List</a></p>
        </div>
    `;
}

// Function to display CVE details
function displayCveDetails(data) {
    try {
        const cve = data.cve;
        
        // Set description - Get English description from descriptions array
        const englishDesc = cve.descriptions.find(desc => desc.lang === 'en');
        document.getElementById("description").textContent = englishDesc ? englishDesc.value : 
            (cve.descriptions.length > 0 ? cve.descriptions[0].value : "No description available");
        
        // Get CVSS v2 data from metrics
        if (cve.metrics && cve.metrics.cvssMetricV2 && cve.metrics.cvssMetricV2.length > 0) {
            const cvssV2 = cve.metrics.cvssMetricV2[0];
            const cvssData = cvssV2.cvssData;
            
            // Set CVSS v2 basic info
            document.getElementById("cvss-v2-severity").textContent = cvssV2.baseSeverity || "N/A";
            document.getElementById("cvss-v2-score").textContent = cvssData.baseScore || "N/A";
            document.getElementById("cvss-v2-vector").textContent = cvssData.vectorString || "N/A";
            
            // Set impact metrics
            document.getElementById("access-vector").textContent = cvssData.accessVector || "N/A";
            document.getElementById("access-complexity").textContent = cvssData.accessComplexity || "N/A";
            document.getElementById("authentication").textContent = cvssData.authentication || "N/A";
            document.getElementById("confidentiality-impact").textContent = cvssData.confidentialityImpact || "N/A";
            document.getElementById("integrity-impact").textContent = cvssData.integrityImpact || "N/A";
            document.getElementById("availability-impact").textContent = cvssData.availabilityImpact || "N/A";
            
            // Set scores
            document.getElementById("exploitability-score").textContent = cvssV2.exploitabilityScore || "N/A";
            document.getElementById("impact-score").textContent = cvssV2.impactScore || "N/A";
        } else {
            // Handle missing CVSS data
            const elementsToUpdate = [
                "cvss-v2-severity", "cvss-v2-score", "cvss-v2-vector",
                "access-vector", "access-complexity", "authentication",
                "confidentiality-impact", "integrity-impact", "availability-impact",
                "exploitability-score", "impact-score"
            ];
            
            elementsToUpdate.forEach(id => {
                document.getElementById(id).textContent = "N/A";
            });
        }
        
        // Set CPE data from configurations
        const cpeTable = document.getElementById("cpe-table").getElementsByTagName('tbody')[0];
        cpeTable.innerHTML = ''; // Clear existing data
        
        if (cve.configurations && cve.configurations.length > 0) {
            let cpeMatches = [];
            
            // Extract CPE matches from all configurations
            cve.configurations.forEach(config => {
                if (config.nodes) {
                    config.nodes.forEach(node => {
                        if (node.cpeMatch) {
                            cpeMatches = cpeMatches.concat(node.cpeMatch);
                        }
                    });
                }
            });
            
            if (cpeMatches.length > 0) {
                cpeMatches.forEach(cpe => {
                    const row = document.createElement("tr");
                    row.innerHTML = `
                        <td>${cpe.criteria || "N/A"}</td>
                        <td>${cpe.matchCriteriaId || "N/A"}</td>
                        <td>${cpe.vulnerable ? "Yes" : "No"}</td>
                    `;
                    cpeTable.appendChild(row);
                });
            } else {
                addNoCpeDataRow(cpeTable);
            }
        } else {
            addNoCpeDataRow(cpeTable);
        }
    } catch (error) {
        console.error("Error displaying CVE details:", error);
        displayError("Error processing CVE data. The data format may be unexpected.");
    }
}

// Helper function to add a "No CPE data" row
function addNoCpeDataRow(table) {
    const row = document.createElement("tr");
    row.innerHTML = `
        <td colspan="3" style="text-align: center;">No CPE data available</td>
    `;
    table.appendChild(row);
}
