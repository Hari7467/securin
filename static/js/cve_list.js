document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const cveTableBody = document.getElementById('cve-table-body');
    const totalCountElement = document.getElementById('total-count');
    const resultsPerPageSelect = document.getElementById('results-per-page');
    const prevPageButton = document.getElementById('prev-page');
    const nextPageButton = document.getElementById('next-page');
    const pageNumbersContainer = document.getElementById('page-numbers');
    const sortableHeaders = document.querySelectorAll('th.sortable');
    
    // Filters
    const cveIdFilter = document.getElementById('cve-id-filter');
    const yearFilter = document.getElementById('year-filter');
    const minScoreFilter = document.getElementById('min-score-filter');
    const maxScoreFilter = document.getElementById('max-score-filter');
    const lastModifiedDaysFilter = document.getElementById('last-modified-days-filter');
    const applyFiltersButton = document.getElementById('apply-filters');
    const clearFiltersButton = document.getElementById('clear-filters');
    
    // State variables
    let currentPage = 1;
    let totalPages = 1;
    let resultsPerPage = 10;
    let sortField = 'cve.published';
    let sortOrder = -1; // -1 for descending, 1 for ascending
    let activeFilters = {};
    
    // Initialize the data
    loadCveData();
    
    // Event listeners
    resultsPerPageSelect.addEventListener('change', function() {
        resultsPerPage = parseInt(this.value);
        currentPage = 1; // Reset to first page
        loadCveData();
    });
    
    prevPageButton.addEventListener('click', function() {
        if (currentPage > 1) {
            currentPage--;
            loadCveData();
        }
    });
    
    nextPageButton.addEventListener('click', function() {
        if (currentPage < totalPages) {
            currentPage++;
            loadCveData();
        }
    });
    
    sortableHeaders.forEach(header => {
        header.addEventListener('click', function() {
            const field = this.getAttribute('data-field');
            
            // Toggle sort order if clicking on the same header
            if (field === sortField) {
                sortOrder = sortOrder === 1 ? -1 : 1;
            } else {
                sortField = field;
                sortOrder = -1; // Default to descending
            }
            
            // Update sort indicators
            updateSortIndicators();
            
            // Reload data with new sort
            loadCveData();
        });
    });
    
    applyFiltersButton.addEventListener('click', function() {
        // Reset to first page when applying filters
        currentPage = 1;
        
        // Collect filter values
        activeFilters = {};
        
        if (cveIdFilter.value.trim()) {
            activeFilters.cve_id = cveIdFilter.value.trim();
        }
        
        if (yearFilter.value.trim()) {
            activeFilters.year = yearFilter.value.trim();
        }
        
        if (minScoreFilter.value.trim()) {
            activeFilters.min_score = minScoreFilter.value.trim();
        }
        
        if (maxScoreFilter.value.trim()) {
            activeFilters.max_score = maxScoreFilter.value.trim();
        }
        
        if (lastModifiedDaysFilter.value.trim()) {
            activeFilters.last_modified_days = lastModifiedDaysFilter.value.trim();
        }
        
        loadCveData();
    });
    
    clearFiltersButton.addEventListener('click', function() {
        // Reset all filters
        cveIdFilter.value = '';
        yearFilter.value = '';
        minScoreFilter.value = '';
        maxScoreFilter.value = '';
        lastModifiedDaysFilter.value = '';
        
        // Clear active filters
        activeFilters = {};
        
        // Reset to first page
        currentPage = 1;
        
        // Reload data
        loadCveData();
    });
    
    // Function to load CVE data from the API
    function loadCveData() {
        // Construct the API URL with query parameters
        let apiUrl = `/api/cves?page=${currentPage}&results_per_page=${resultsPerPage}&sort_field=${sortField}&sort_order=${sortOrder}`;
        
        // Add active filters to the URL
        Object.keys(activeFilters).forEach(key => {
            apiUrl += `&${key}=${encodeURIComponent(activeFilters[key])}`;
        });
        
        // Show loading state
        cveTableBody.innerHTML = '<tr><td colspan="5" class="text-center">Loading...</td></tr>';
        
        // Fetch data from the API
        fetch(apiUrl)
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(data => {
                // Update total count
                totalCountElement.textContent = data.total_count;
                
                // Update pagination
                totalPages = data.total_pages;
                updatePagination();
                
                // Clear table body
                cveTableBody.innerHTML = '';
                
                // Populate table with CVE data
                if (data.cves.length === 0) {
                    cveTableBody.innerHTML = '<tr><td colspan="5" class="text-center">No CVEs found</td></tr>';
                } else {
                    data.cves.forEach(cve => {
                        const row = document.createElement('tr');
                        
                        // Add click handler to navigate to detail page
                        row.addEventListener('click', function() {
                            window.location.href = `/cves/${cve.cve_id}`;
                        });
                        
                        // Format dates
                        const publishedDate = new Date(cve.published_date);
                        const lastModifiedDate = new Date(cve.last_modified_date);
                        
                        // Add table cells
                        row.innerHTML = `
                            <td>${cve.cve_id}</td>
                            <td>${cve.identifier}</td>
                            <td>${publishedDate.toLocaleDateString()}</td>
                            <td>${lastModifiedDate.toLocaleDateString()}</td>
                            <td>${cve.status}</td>
                        `;
                        
                        cveTableBody.appendChild(row);
                    });
                }
            })
            .catch(error => {
                console.error('Error fetching CVE data:', error);
                cveTableBody.innerHTML = '<tr><td colspan="5" class="text-center">Error loading CVE data</td></tr>';
            });
    }
    
    // Function to update pagination UI
    function updatePagination() {
        // Update prev/next button states
        prevPageButton.disabled = currentPage <= 1;
        nextPageButton.disabled = currentPage >= totalPages;
        
        // Generate page number buttons
        pageNumbersContainer.innerHTML = '';
        
        // Determine range of page numbers to show
        let startPage = Math.max(1, currentPage - 2);
        let endPage = Math.min(totalPages, startPage + 4);
        
        if (endPage - startPage < 4 && totalPages > 4) {
            startPage = Math.max(1, endPage - 4);
        }
        
        // Add first page button if not included in range
        if (startPage > 1) {
            const pageButton = createPageButton(1);
            pageNumbersContainer.appendChild(pageButton);
            
            if (startPage > 2) {
                pageNumbersContainer.appendChild(createEllipsis());
            }
        }
        
        // Add page number buttons
        for (let i = startPage; i <= endPage; i++) {
            const pageButton = createPageButton(i);
            pageNumbersContainer.appendChild(pageButton);
        }
        
        // Add last page button if not included in range
        if (endPage < totalPages) {
            if (endPage < totalPages - 1) {
                pageNumbersContainer.appendChild(createEllipsis());
            }
            
            const pageButton = createPageButton(totalPages);
            pageNumbersContainer.appendChild(pageButton);
        }
    }
    
    // Function to create a page number button
    function createPageButton(pageNum) {
        const button = document.createElement('button');
        button.textContent = pageNum;
        button.className = 'btn page-btn';
        
        if (pageNum === currentPage) {
            button.classList.add('active');
        }
        
        button.addEventListener('click', function() {
            currentPage = pageNum;
            loadCveData();
        });
        
        return button;
    }
    
    // Function to create ellipsis element
    function createEllipsis() {
        const span = document.createElement('span');
        span.textContent = '...';
        span.className = 'page-ellipsis';
        span.style.padding = '0 10px';
        return span;
    }
    
    // Function to update sort indicators in table headers
    function updateSortIndicators() {
        sortableHeaders.forEach(header => {
            const field = header.getAttribute('data-field');
            const indicator = header.querySelector('.sort-indicator');
            
            // Remove all sort classes
            indicator.classList.remove('sort-asc', 'sort-desc');
            
            // Add appropriate sort class if this is the active sort field
            if (field === sortField) {
                indicator.classList.add(sortOrder === 1 ? 'sort-asc' : 'sort-desc');
            }
        });
    }
    
    // Initialize sort indicators
    updateSortIndicators();
});