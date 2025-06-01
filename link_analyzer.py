# From 'flask' a package used to build web applications and APIs, import the following libraries;
# Flask => for setting up the core web application
# request => for holding incoming data from client's web browser or other HTTP client
# render_template_string => renders template directly from a string of template code rather than a separate template file

# import re (Regular Expressions) for URL routing
# import tldextract, a package that can accurately separate a URL into meaningful components

from flask import Flask, render_template_string, request
import re
import tldextract

# Simulating an API check, we can make a list of malicious links
# In the future, this section could involve Artificial Intelligence concepts such as ML
malicious_links = ["http://fakejob.com", "http://phishsite.com"]

# Lists for suspicious patterns
shorteners = ["bit.ly", "tinyurl.com", "goo.gl"]
keywords = ["login", "verify", "account", "bank", "password"]
common_tlds = ["com", "org", "net", "edu", "gov"]


# Function to extract links from text
def extract_links(text):
    return re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)


# Function to analyze a single link
def analyze_link(link):
    # Check if link is in the list of malicious links
    if link in malicious_links:
        return "Malicious", "Known malicious link"

    # Checks for suspicious patterns
    extracted = tldextract.extract(link)
    domain = f"{extracted.domain}.{extracted.suffix}"
    subdomains = extracted.subdomain.split(".") if extracted.subdomain else []

    if domain in shorteners:
        return "Potentially malicious", "Uses URL shortener"
    if any(keyword in link.lower() for keyword in keywords):
        return "Potentially malicious", "Contains suspicious keywords"
    if len(subdomains) > 2:
        return "Potentially malicious", "Excessive subdomains"
    if extracted.suffix not in common_tlds:
        return "Potentially malicious", "Uncommon TLD"

    return "Safe", "No issues found"


# Flask app setup
app = Flask(__name__)

# HTML template for the input form
FORM_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Link Analyzer</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 20px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            color: #333;
        }
        h1 {
            color: #0056b3;
        }
        form {
            background-color: #fff;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 500px;
            text-align: center;
        }
        textarea {
            width: calc(100% - 20px);
            padding: 10px;
            margin-bottom: 20px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box; /* Include padding and border in the element's total width and height */
            resize: vertical;
        }
        input[type="submit"] {
            background-color: #007bff;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            transition: background-color 0.3s ease;
        }
        input[type="submit"]:hover {
            background-color: #0056b3;
        }
        p {
            margin-bottom: 20px;
            font-size: 1.1em;
        }
    </style>
</head>
<body>
    <h1>Simple Link Safety Analyzer</h1>
    <p>Paste your messages below to analyze links:</p>
    <form method="post">
        <textarea name="messages" rows="10" cols="50" placeholder="Paste your messages here..."></textarea><br>
        <input type="submit" value="Analyze">
    </form>
</body>
</html>
'''

# HTML template for displaying results
RESULTS_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Link Analyzer Results</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 20px;
            display: flex;
            flex-direction: column;
            align-items: center;
            min-height: 100vh;
            color: #333;
        }
        h1 {
            color: #0056b3;
            margin-bottom: 30px;
        }
        ul {
            list-style: none;
            padding: 0;
            width: 100%;
            max-width: 600px;
        }
        li {
            background-color: #fff;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        li strong {
            color: #007bff;
        }
        .Malicious {
            color: #dc3545; /* Red for malicious */
            font-weight: bold;
        }
        .Potentially-malicious {
            color: #ffc107; /* Orange for potentially malicious */
            font-weight: bold;
        }
        .Safe {
            color: #28a745; /* Green for safe */
            font-weight: bold;
        }
        a {
            display: inline-block;
            margin-top: 20px;
            background-color: #6c757d;
            color: white;
            padding: 10px 20px;
            border-radius: 5px;
            text-decoration: none;
            transition: background-color 0.3s ease;
        }
        a:hover {
            background-color: #5a6268;
        }
    </style>
</head>
<body>
    <h1>Analysis Results</h1>
    <ul>
        {% for result in results %}
        <li>
            <strong>Link:</strong> {{ result.link }}<br>
            <strong>Classification:</strong> <span class="{{ result.classification.replace(' ', '-') }}">{{ result.classification }}</span><br>
            <strong>Reason:</strong> {{ result.reason }}
        </li>
        {% endfor %}
    </ul>
    <a href="/">Analyze another message</a>
</body>
</html>
'''

# Route for handling form submission and displaying results
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        text = request.form['messages']
        links = extract_links(text)
        results = []
        for link in links:
            classification, reason = analyze_link(link)
            results.append({'link': link, 'classification': classification, 'reason': reason})
        return render_template_string(RESULTS_TEMPLATE, results=results)
    else:
        return render_template_string(FORM_TEMPLATE)


if __name__ == '__main__':
    app.run(debug=True)