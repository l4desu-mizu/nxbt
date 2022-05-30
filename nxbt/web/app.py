import json
import os
from threading import RLock

from socket import gethostname

from .cert import generate_cert
from ..nxbt import Nxbt, PRO_CONTROLLER
from flask import Flask, render_template, request
from flask_socketio import SocketIO
import eventlet
import logging

logger = logging.getLogger(__name__)

app = Flask(__name__,
            static_url_path='',
            static_folder='static',)
nxbt = Nxbt()

# Configuring/retrieving secret key
secrets_path = os.path.join(
    os.path.dirname(__file__), "secrets.txt"
)
if not os.path.isfile(secrets_path):
    secret_key = os.urandom(24).hex()
    with open(secrets_path, "w") as f:
        f.write(secret_key)
else:
    with open(secrets_path, "r") as f:
        secret_key = f.read()
app.config['SECRET_KEY'] = secret_key

# Starting socket server with Flask app
sio = SocketIO(app, cookie=False)

user_info_lock = RLock()
USER_INFO = {}


@app.route('/')
def index():
    return render_template('index.html')


@sio.on('connect')
def on_connect():
    with user_info_lock:
        USER_INFO[request.sid] = {}


@sio.on('state')
def on_state(*_params):
    state_proxy = nxbt.state.copy()
    state = {}
    for controller in state_proxy.keys():
        state[controller] = state_proxy[controller].copy()
    return state


@sio.on('disconnect')
def on_disconnect(*_params):
    with user_info_lock:
        try:
            controller_index = USER_INFO[request.sid]["controller_index"]
            nxbt.remove_controller(controller_index)
        except KeyError:
            pass


@sio.on('shutdown')
def on_shutdown(controller_index):
    nxbt.remove_controller(controller_index)


@sio.on('create_pro_controller')
def on_create_controller(*_params):
    try:
        reconnect_addresses = nxbt.get_switch_addresses()
        controller_index = nxbt.create_controller(PRO_CONTROLLER, reconnect_address=reconnect_addresses)

        with user_info_lock:
            USER_INFO[request.sid]["controller_index"] = controller_index
        return controller_index
    except Exception as e:
        return e


@sio.on('input')
def handle_input(message):
    message = json.loads(message)
    controller_index = message[0]
    input_packet = message[1]
    try:
        nxbt.set_controller_input(controller_index, input_packet)
    except ValueError as e:
        logger.warning(e)


@sio.on('macro')
def handle_macro(message):
    message = json.loads(message)
    controller_index = message[0]
    macro = message[1]
    nxbt.macro(controller_index, macro)


def start_web_app(ip='0.0.0.0', port=8000, usessl=False, cert_path=None):
    if usessl:
        if cert_path is None:
            # Store certs in the package directory
            cert_path = os.path.join(
                os.path.dirname(__file__), "cert.pem"
            )
            key_path = os.path.join(
                os.path.dirname(__file__), "key.pem"
            )
        else:
            # If specified, store certs at the user's preferred location
            cert_path = os.path.join(
                cert_path, "cert.pem"
            )
            key_path = os.path.join(
                cert_path, "key.pem"
            )
        if not os.path.isfile(cert_path) or not os.path.isfile(key_path):
            print(
                "\n"
                "-----------------------------------------\n"
                "---------------->WARNING<----------------\n"
                "The NXBT webapp is being run with self-\n"
                "signed SSL certificates for use on your\n"
                "local network.\n"
                "\n"
                "These certificates ARE NOT safe for\n"
                "production use. Please generate valid\n"
                "SSL certificates if you plan on using the\n"
                "NXBT webapp anywhere other than your own\n"
                "network.\n"
                "-----------------------------------------\n"
                "\n"
                "The above warning will only be shown once\n"
                "on certificate generation."
                "\n"
            )
            print("Generating certificates...")
            cert, key = generate_cert(gethostname())
            with open(cert_path, "wb") as f:
                f.write(cert)
            with open(key_path, "wb") as f:
                f.write(key)

        eventlet.wsgi.server(eventlet.wrap_ssl(eventlet.listen((ip, port)),
            certfile=cert_path, keyfile=key_path), app)
    else:
        eventlet.wsgi.server(eventlet.listen((ip, port)), app)


if __name__ == "__main__":
    start_web_app()
