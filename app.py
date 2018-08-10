# Clever Partner Engineering Take-Home Project - Feb 3, 2017
# Uses the Flask microframework and HTTP requests to facilitate the Clever Instant Login flow.

import base64
from base64 import b64encode
import requests
import urllib
import threading
import time
import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, json, redirect, session, url_for

#  Initialize constants.
CLIENT_ID = 'dab7a1d7898721cda256'
CLIENT_SECRET = '27cceb78bcb3c81728d0fc3a748c68e7f823fc9a'
REDIRECT_URI = 'https://clever-takehome.herokuapp.com/oauth'
DISTRICT_ID = '588bbf9c837c7f00017667b6'
CLEVER_AUTH_URL = 'https://clever.com/oauth/authorize'
CLEVER_TOKEN_URL = 'https://clever.com/oauth/tokens'
CLEVER_API_ME_URL = 'https://api.clever.com/me'

# Initialize dictionary for storing recent authorization codes and associated lock object.
recent_codes = {}
recent_codes_lock = threading.Lock()

# Initialize Flask application.
app = Flask(__name__)

# Handler for showing the index page which will present a Clever Instant Login button using the encoded query parameters.
@app.route('/')
def index():
	# Render the index.html page and pass an encoded query string to help create the Clever Login button.
	return render_template('index.html', query_string=generate_encoded_query_string())
	
# OAuth handler.
@app.route('/oauth')
def oauth():
	# Check if a state parameters was passed in the query string and if it matches the user's session state parameter.	
	if request.args.get('state') is None or not session['state']:
		# Automatically redirect back to Clever with new state parameter.
		return redirect(CLEVER_AUTH_URL + '?' + generate_encoded_query_string(), 302)
	else:
		# Retrieve the authorization code from the query string.
		code = request.args.get('code')

		# Acquire a lock for thread safety.
		recent_codes_lock.acquire()

		# This logic checks for repeat codes to ensure they are not used twice.
		if code in (recent_codes):	
			# Release the lock.
			recent_codes_lock.release()
			
			# Automatically redirect the user back to Clever to retrieve a new code.
			return redirect(CLEVER_AUTH_URL + '?' + generate_encoded_query_string(), 302)
		else:
			# If code is valid, add it to dictionary of recent codes with a timestamp.
			recent_codes[code] = datetime.now()
		
		# Release the lock.
		recent_codes_lock.release()

		# Prepare HTTP POST body to exchange code for token.
		body = {'code': code, 'grant_type': 'authorization_code', 'redirect_uri': REDIRECT_URI}

		# Create headers using encoded application credentials.
		headers = {
			'Authorization': 'Basic {base64string}'.format(base64string =
				base64.b64encode(CLIENT_ID + ':' + CLIENT_SECRET)),
			'Content-Type': 'application/json',
		}

		# Get response from HTTP POST to Clever's token URL.
		r = requests.post(CLEVER_TOKEN_URL, json=body, headers=headers).json()

		# Try to store the retrieved token. If somehow the code was already used, automatically redirect to retrive a new code.
		try:
			token = r["access_token"]
		except (KeyError) as error:
			return redirect(CLEVER_AUTH_URL + '?' + generate_encoded_query_string(), 302)
		
		# Print token
		print "token = " + token
		
		# Use the token to create headers for requests to Clever's API.
		auth_headers = {'Authorization': 'Bearer {token}'.format(token=token)}
		
		# Request data from the Clever API /me endpoint using the token.
		d = requests.get(CLEVER_API_ME_URL, headers=auth_headers)
	    
		# Handle Clever's 4xx and 5xx errors as specified on https://dev.clever.com/api-overview/responses.
		if d.status_code in (400, 401):
			return 'Error 400/401: Bad request. Check your API token and request body.'
		if d.status_code == (404):
			return 'Error 404: Resource not available. Check your request url. Resource may have been deleted from Clever.'
		if d.status_code == (413):
			return 'Error 413: Request entity too large. Either a page parameter is over 100 or a limit parameter is over 10,000; reduce accordingly.'
		if d.status_code == (429):
			return 'Error 429: Rate limit exceeded.  Try again in 1 minute'
		if d.status_code in (500, 502, 503):
			return 'Error 500/502/503: Clever API Failure.  Try again with exponential backoff'
		if d.status_code == (501):
			return 'Error 501: Not Implemented. This request is not supported.'
		else:
			# Get the data type from the JSON response from the Clever endpoint and store contents in the user's Flask session.
			session['clever_data'] = d.json()
			print "json: " + d.json()
			return redirect('/application')

# Application handler reserved for users who have successfully logged in.
@app.route('/application')
def application():
	# Check to see if user is logged in.
	if 'clever_data' not in session:
		# Redirect user to index page to login.
		return redirect('/')
	else:
		# Render the application page with the response from the Clever API for logged in users and provide a logout link.
		return render_template('app.html', data=json.dumps(session['clever_data']), logout_url=url_for('logout'))

# Exception handler that returns a 500 status code.
@app.errorhandler(500)
def all_exception_handler(error):
   return '500 Error', 500

# Logout handler that clears the user's Flask session.
@app.route('/logout')
def logout():
	session.clear()
	return 'Captain, you are now logged out.'

# Method that generates a new random string to use as a state parameter and returns an encoded query string.
def generate_encoded_query_string():
	# Generate a new random string and store it in the user's Flask session.
	session['state'] = b64encode(os.urandom(12)).decode('utf-8')
	
	# Generate an encoded query string using application constants and the new random string as a state parameter.
	query_string = urllib.urlencode({'response_type': 'code', 'client_id': CLIENT_ID, 'redirect_uri': REDIRECT_URI, 'district_id': DISTRICT_ID, 'state': session['state']})
	return query_string

# Method that checks the recent_codes dictionary and removes codes that are older than one hour.
def recent_codes_cleanup():
	# Loop forever.
	while True:
		# Acquire a lock for thread safety.
		recent_codes_lock.acquire()
		# Iterate on every code and timestamp pair in recent_codes.
		for code, timestamp in recent_codes.iteritems():
			# Check if the timestamp is older than one hour.
			if datetime.now() - timestamp > timedelta(seconds=3600):
				# Remove code from recent_codes.
				recent_codes.pop(code, None)
		# Release the lock and sleep for 60 seconds.
		recent_codes_lock.release()
		time.sleep(60) 

# Random key generated from os.urandom(24) to enable use of Flask sessions.
app.secret_key ='\kpd{H\xe5<\x95\xf9\xe3\x96.5\xd1\x01O<!\xe3\xa2\xa0\x9fR"\xa1\xa8'

# Main method.
if __name__== "__main__":
	# Create thread object and start thread.
	thread = threading.Thread(target=recent_codes_cleanup)
	thread.start()

	# Start Flask server.
	app.run()
