''' Example of Spotify authorization code flow (refreshable user auth).

Displays profile information of authenticated user and access token
information that can be refreshed by clicking a button.

Basic flow:
    -> '/'
    -> Spotify login page
    -> '/callback'
    -> get tokens
    -> use tokens to access API

Required environment variables:
    FLASK_APP, CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, SECRET_KEY

More info:
    https://developer.spotify.com/documentation/general/guides/authorization-guide/#authorization-code-flow

'''
import os
if int(os.environ.get('DEBUG')) == 1:
    debug = True
else:
    debug = False
  # when i run locally True, when I deploy it False

from flask import (
    abort,
    Flask,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
    flash,
)
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)

from flask_talisman import Talisman
import json
import requests
import secrets
import string
from urllib.parse import urlencode
import spotipy
import datetime
from datetime import datetime
import redis
import os
import json
from oauthlib.oauth2 import WebApplicationClient
import random
import spotipy.util as util



#r = redis.from_url(os.environ.get("REDIS_URL"))

# Client info
CLIENT_ID = os.environ.get("SPOTIPY_CLIENT_ID")
CLIENT_SECRET = os.environ.get("SPOTIPY_CLIENT_SECRET")

if debug:
    REDIRECT_URI = 'http://127.0.0.1:5000/callback'
else:
    REDIRECT_URI = 'https://fizzl.herokuapp.com/callback'

# Spotify API endpoints
AUTH_URL = 'https://accounts.spotify.com/authorize'
TOKEN_URL = 'https://accounts.spotify.com/api/token'
ME_URL = 'https://api.spotify.com/v1/me'

# Start 'er up
app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET_KEY")
#Talisman(app)


#login_manager.init_app(app)
Talisman(app, content_security_policy=None)
#Talisman(app)

scope = 'user-library-read playlist-modify-public'


#r.mset({"tracks": json.dumps(track_dict)})
#print(json.loads(r.mget("tracks")[0].decode()).get("song2"))


"""@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)"""

@app.route("/")
def index():
    return render_template("index.html")





@app.route('/<loginout>')
def login(loginout):
    '''Login or logout user.

    Note:
        Login and logout process are essentially the same.  Logout forces
        re-login to appear, even if their token hasn't expired.
    '''

    # redirect_uri can be guessed, so let's generate
    # a random `state` string to prevent csrf forgery.
    state = ''.join(
        secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16)
    )

    # Request authorization from user
    scope = "user-read-private user-top-read"

    if loginout == 'logout':
        payload = {
            'client_id': CLIENT_ID,
            'response_type': 'code',
            'redirect_uri': REDIRECT_URI,
            'state': state,
            'scope': scope,
            'show_dialog': True,
        }
    elif loginout == 'login':
        payload = {
            'client_id': CLIENT_ID,
            'response_type': 'code',
            'redirect_uri': REDIRECT_URI,
            'state': state,
            'scope': scope,
        }
    else:
        abort(404)

    res = make_response(redirect(f'{AUTH_URL}/?{urlencode(payload)}'))
    res.set_cookie('spotify_auth_state', state)

    return res


@app.route('/callback')
def callback():
    error = request.args.get('error')
    code = request.args.get('code')
    state = request.args.get('state')
    stored_state = request.cookies.get('spotify_auth_state')

    # Check state
    if state is None or state != stored_state:
        app.logger.error('Error message: %s', repr(error))
        app.logger.error('State mismatch: %s != %s', stored_state, state)
        abort(400)

    # Request tokens with code we obtained
    payload = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
    }

    # `auth=(CLIENT_ID, SECRET)` basically wraps an 'Authorization'
    # header with value:
    # b'Basic ' + b64encode((CLIENT_ID + ':' + SECRET).encode())
    res = requests.post(TOKEN_URL, auth=(CLIENT_ID, CLIENT_SECRET), data=payload)
    res_data = res.json()

    if res_data.get('error') or res.status_code != 200:
        app.logger.error(
            'Failed to receive token: %s',
            res_data.get('error', 'No error information received.'),
        )
        abort(res.status_code)

    # Load tokens into session
    session['tokens'] = {
        'access_token': res_data.get('access_token'),
        'refresh_token': res_data.get('refresh_token'),
    }

    return redirect(url_for('playlists'))


@app.route('/refresh')
def refresh():
    '''Refresh access token.'''

    payload = {
        'grant_type': 'refresh_token',
        'refresh_token': session.get('tokens').get('refresh_token'),
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    res = requests.post(
        TOKEN_URL, auth=(CLIENT_ID, CLIENT_SECRET), data=payload, headers=headers
    )
    res_data = res.json()

    # Load new token into session
    session['tokens']['access_token'] = res_data.get('access_token')

    return json.dumps(session['tokens'])

@app.route('/playlists')
def playlists():
    if not session.get('tokens') or not session.get('tokens').get('access_token'):
        return redirect(url_for('index'))
    if session['tokens'].get('access_token'):
        sp = spotipy.Spotify(auth=session['tokens'].get('access_token'))  # create spotify session
        playlists = sp.user_playlists(user=sp.me()['id'])
        print(playlists)
        playlists_recent = playlists['items'][:20]
        p_output = []
        for i, playlist in enumerate(playlists_recent):
                p_output.append([playlist['id'], playlist['name']])
        return render_template("playlists.html", playlists=p_output)




if __name__ == "__main__":
    if debug:
        app.run(debug=True)

    else:
        app.run(debug=False)
