from flask import Flask, request, render_template
import os
import re
import homoglyphs as hg

app = Flask(__name__, template_folder='templatess')  # ← This line is updated

homoglyphs_obj = hg.Homoglyphs(languages={'en', 'ru', 'el'})

def extract_links(text):
    url_pattern = re.compile(
        r'((?:https?://|www\.)[^\s]+|[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?)'
    )
    return url_pattern.findall(text)

def is_link_suspicious(link):
    ascii_versions = homoglyphs_obj.to_ascii(link)
    return bool(ascii_versions and (link not in ascii_versions))

@app.route('/', methods=['GET', 'POST'])
def index():
    results = None
    if request.method == 'POST':
        text = ""
        if 'text' in request.form:
            text = request.form['text']
        elif 'file' in request.files:
            file = request.files['file']
            if file:
                text = file.read().decode('utf-8')

        links = extract_links(text)
        suspicious_links = [link for link in links if is_link_suspicious(link)]
        results = {
            'all_links': links,
            'suspicious_links': suspicious_links
        }

    return render_template('index.html', results=results)

if __name__ == '__main__':
    app.run(debug=True)
