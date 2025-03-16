from flask import Flask, jsonify, request, render_template
import requests
import time
import pymongo
from pymongo import MongoClient
from datetime import datetime, timedelta
import threading
import schedule
import json

app = Flask(__name__)

# MongoDB connection
client = MongoClient("mongodb+srv://harivijayan2004:97041208@cluster0.jpzey.mongodb.net/?retryWrites=true&w=majority&tls=true&tlsAllowInvalidCertificates=true")
db = client['cve_db']
cve_collection = db['cve_records']

# Create indexes for better query performance
cve_collection.create_index('cve.id')
cve_collection.create_index('cve.published')
cve_collection.create_index('cve.lastModified')
cve_collection.create_index('cve.metrics.cvssMetricV2.cvssData.baseScore')
cve_collection.create_index('cve.metrics.cvssMetricV3.cvssData.baseScore')

# NVD API Configuration
NVD_API_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
RESULTS_PER_REQUEST = 2000  # Maximum allowed by the API
API_KEY = None  # Optional: Add your API key if you have one

# Rate limiting (NVD API allows 5 requests per 30 seconds for unauthenticated users)
REQUEST_DELAY = 6  # seconds between requests for unauthenticated access

# Function to fetch data from NVD API
def fetch_cve_data(start_index=0, results_per_page=2000):
    params = {
        'startIndex': start_index,
        'resultsPerPage': results_per_page
    }
    
    headers = {}
    if API_KEY:
        headers['apiKey'] = API_KEY
    
    try:
        response = requests.get(NVD_API_BASE_URL, params=params, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"API request failed with status code: {response.status_code}")
            print(f"Response: {response.text}")
            return None
    except Exception as e:
        print(f"Error fetching data from NVD API: {e}")
        return None

# Process and store CVE data in MongoDB
def process_and_store_data(cve_data):
    if not cve_data or 'vulnerabilities' not in cve_data:
        return 0
    
    count = 0
    for vuln in cve_data['vulnerabilities']:
        # Extract CVE ID
        cve_id = vuln['cve']['id']
        
        # Check if the CVE already exists in the database
        existing_cve = cve_collection.find_one({'cve.id': cve_id})
        
        if existing_cve:
            # Update the existing record
            cve_collection.update_one(
                {'cve.id': cve_id},
                {'$set': vuln}
            )
        else:
            # Insert new record
            cve_collection.insert_one(vuln)
        
        count += 1
    
    return count

# Initial data synchronization
def initial_data_sync():
    print("Starting initial data synchronization...")
    total_fetched = 0
    start_index = 0
    
    while True:
        print(f"Fetching CVEs starting from index {start_index}...")
        data = fetch_cve_data(start_index)
        
        if not data or 'vulnerabilities' not in data:
            print("No more data to fetch or API error occurred.")
            break
        
        processed = process_and_store_data(data)
        total_fetched += processed
        
        print(f"Processed {processed} CVEs. Total so far: {total_fetched}")
        
        # Check if we've reached the end of the data
        if 'totalResults' in data and start_index + RESULTS_PER_REQUEST >= data['totalResults']:
            print(f"Completed initial sync. Total CVEs: {total_fetched}")
            break
        
        # Move to the next batch
        start_index += RESULTS_PER_REQUEST
        
        # Respect the rate limit
        time.sleep(REQUEST_DELAY)
    
    return total_fetched

# Periodic sync function (for incremental updates)
def periodic_sync():
    # Get the timestamp of the most recently updated CVE
    latest_cve = cve_collection.find_one(sort=[("cve.lastModified", pymongo.DESCENDING)])
    
    # If we have records, only fetch ones modified after our latest
    if latest_cve and 'cve' in latest_cve and 'lastModified' in latest_cve['cve']:
        last_modified = latest_cve['cve']['lastModified']
        print(f"Fetching CVEs modified after {last_modified}")
        
        # Add lastModifiedStartDate parameter to the API call
        params = {
            'startIndex': 0,
            'resultsPerPage': RESULTS_PER_REQUEST,
            'lastModStartDate': last_modified
        }
        
        headers = {}
        if API_KEY:
            headers['apiKey'] = API_KEY
        
        try:
            response = requests.get(NVD_API_BASE_URL, params=params, headers=headers)
            if response.status_code == 200:
                data = response.json()
                processed = process_and_store_data(data)
                print(f"Updated {processed} CVEs")
            else:
                print(f"API request failed with status code: {response.status_code}")
        except Exception as e:
            print(f"Error during periodic sync: {e}")
    else:
        # If no records exist, perform a full sync
        print("No existing records found. Performing full sync.")
        initial_data_sync()

# Schedule periodic sync (every 24 hours)
def start_scheduler():
    schedule.every(24).hours.do(periodic_sync)
    
    while True:
        schedule.run_pending()
        time.sleep(3600)  # Check every hour if a sync is due

# Start the scheduler in a separate thread
with app.app_context():  
    count = cve_collection.count_documents({})
    if count == 0:
        print("No CVE data found. Starting initial synchronization...")
        threading.Thread(target=initial_data_sync, daemon=True).start()
    else:
        print(f"Found {count} existing CVE records. Skipping initial sync.")

    # Start the periodic sync scheduler
    threading.Thread(target=start_scheduler, daemon=True).start()


# API Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/cves/list')
def cves_list():
    return render_template('cves_list.html')

@app.route('/cves/<cve_id>')
def cve_detail(cve_id):
    return render_template('cve_detail.html', cve_id=cve_id)

# API Endpoints
@app.route('/api/cves', methods=['GET'])
def get_cves():
    page = int(request.args.get('page', 1))
    results_per_page = int(request.args.get('results_per_page', 10))
    cve_id = request.args.get('cve_id')
    year = request.args.get('year')
    min_score = request.args.get('min_score')
    max_score = request.args.get('max_score')
    last_modified_days = request.args.get('last_modified_days')
    sort_field = request.args.get('sort_field', 'cve.published')
    sort_order = int(request.args.get('sort_order', -1))  # -1 for descending, 1 for ascending
    
    # Build the query
    query = {}
    
    if cve_id:
        query['cve.id'] = {'$regex': cve_id, '$options': 'i'}
    
    if year:
        query['cve.id'] = {'$regex': f'-{year}-', '$options': 'i'}
    
    if min_score or max_score:
        score_query = {}
        
        if min_score:
            score_query['$gte'] = float(min_score)
        
        if max_score:
            score_query['$lte'] = float(max_score)
        
        # Check both CVSS v2 and v3 scores
        query['$or'] = [
            {'cve.metrics.cvssMetricV2.cvssData.baseScore': score_query},
            {'cve.metrics.cvssMetricV3.cvssData.baseScore': score_query}
        ]
    
    if last_modified_days:
        days = int(last_modified_days)
        date_threshold = datetime.now() - timedelta(days=days)
        date_str = date_threshold.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        query['cve.lastModified'] = {'$gte': date_str}
    
    # Calculate pagination parameters
    skip = (page - 1) * results_per_page
    
    # Get total count for pagination
    total_count = cve_collection.count_documents(query)
    
    # Get the CVEs matching the query
    cves = list(cve_collection.find(
        query,
        {
            'cve.id': 1,
            'cve.sourceIdentifier': 1,
            'cve.published': 1,
            'cve.lastModified': 1,
            'cve.vulnStatus': 1,
            'cve.descriptions': 1,
            'cve.metrics': 1
        }
    ).sort(sort_field, sort_order).skip(skip).limit(results_per_page))
    
    # Format the response
    formatted_cves = []
    for cve in cves:
        # Get CVSS score
        cvss_score = None
        if 'cve' in cve and 'metrics' in cve['cve']:
            metrics = cve['cve']['metrics']
            if 'cvssMetricV3' in metrics and metrics['cvssMetricV3']:
                cvss_score = metrics['cvssMetricV3'][0]['cvssData']['baseScore']
            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss_score = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
        
        # Get description in English
        description = ""
        if 'cve' in cve and 'descriptions' in cve['cve']:
            for desc in cve['cve']['descriptions']:
                if desc['lang'] == 'en':
                    description = desc['value']
                    break
        
        formatted_cve = {
            'cve_id': cve['cve']['id'],
            'identifier': cve['cve']['sourceIdentifier'],
            'published_date': cve['cve']['published'],
            'last_modified_date': cve['cve']['lastModified'],
            'status': cve['cve']['vulnStatus'],
            'cvss_score': cvss_score,
            'description': description
        }
        formatted_cves.append(formatted_cve)
    
    return jsonify({
        'cves': formatted_cves,
        'total_count': total_count,
        'page': page,
        'results_per_page': results_per_page,
        'total_pages': (total_count + results_per_page - 1) // results_per_page
    })

@app.route('/api/cves/<cve_id>', methods=['GET', 'POST'])
def get_cve_by_id(cve_id):
    if request.method == "POST":
        data = request.get_json()
        if not data or 'cve_id' not in data:
            return jsonify({'error': 'Invalid request, CVE ID missing'}), 400

    cve = cve_collection.find_one({'cve.id': cve_id}, {"_id": 0})  # Exclude `_id`
    
    if not cve:
        return jsonify({'error': 'CVE not found'}), 404
    return jsonify(cve)


if __name__ == '__main__':
    app.run(debug=True)