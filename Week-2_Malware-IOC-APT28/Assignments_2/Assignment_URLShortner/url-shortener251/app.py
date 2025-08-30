from flask import Flask, render_template, request, redirect, url_for, flash

app = Flask(__name__, template_folder='templates1')

app.secret_key = 'your_secret_key'  # Needed for flash messages

# Dictionary to store the mappings 
url_map = {}

@app.route('/', methods=['GET', 'POST'])
def home():
    short_url = None  # default value

    if request.method == 'POST':
        long_url = request.form['url']
        alias = request.form['alias']

        if alias in url_map:
            flash('❌ Alias already taken. Try a different one.', 'error')
        else:
            url_map[alias] = long_url
            short_url = request.host_url + alias
            flash('✅ URL shortened successfully!', 'success')

    return render_template('index.html', short_url=short_url)

@app.route('/<alias>')
def redirect_to_url(alias):
    if alias in url_map:
        return redirect(url_map[alias])
    else:
        flash('⚠️ Invalid or expired link.', 'error')
        return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
