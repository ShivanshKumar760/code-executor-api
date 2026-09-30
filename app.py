import os
import re 
import time
import uuid
from flask import Flask, request, jsonify , send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from kubernetes import client, config

app = Flask(__name__, static_folder='static', static_url_path='/static')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'dev-only-fallback')
db = SQLAlchemy(app)
jwt = JWTManager(app)

CODE_ROOT = "/code"                                    # where the shared PVC is mounted in THIS pod
NAMESPACE = os.environ.get('POD_NAMESPACE', 'code-exec')
EXECUTOR_IMAGE = "python:3.11-slim"                     # a plain public image — no custom build needed
print(CODE_ROOT)

# ---------------------------------------------------------------------------
# User model (Flask-SQLAlchemy) — one table, hashed passwords only, never plaintext
# ---------------------------------------------------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

with app.app_context():
    db.create_all()   # fine for this simple demo; a real app would use migrations (Flask-Migrate)


# ---------------------------------------------------------------------------
# Kubernetes API client — load_incluster_config() reads the ServiceAccount
# token Kubernetes automatically mounts into every pod (Section 24's RBAC),
# no kubeconfig file involved at all. This ONLY works when actually running
# inside the cluster — it will fail if you try to run app.py on your laptop.
# ---------------------------------------------------------------------------
config.load_incluster_config()
k8s = client.CoreV1Api()


@app.route('/healthz')
def healthz():
    return "ok", 200


@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    username, password = data.get('username'), data.get('password')
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    # NEW: validate the username format
    if not re.fullmatch(r'[a-z0-9]{3,20}', username):
        return jsonify({"error": "username must be 3-20 lowercase letters/numbers"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "username already taken"}), 409

    user = User(username=username, password_hash=generate_password_hash(password))
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "registered"}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    user = User.query.filter_by(username=data.get('username')).first()
    if not user or not check_password_hash(user.password_hash, data.get('password', '')):
        return jsonify({"error": "bad username or password"}), 401

    token = create_access_token(identity=user.username)
    return jsonify(access_token=token), 200


@app.route('/execute', methods=['POST'])
@jwt_required()
def execute():
    username = get_jwt_identity()
    code = (request.get_json() or {}).get('code')
    if not code:
        return jsonify({"error": "code is required"}), 400

    # 1. Write this submission to its own folder on the shared PVC. The folder
    #    name (username + a random suffix) is exactly what gets used as the
    #    executor pod's `subPath` below, scoping its view to just this folder.
    submission_id = uuid.uuid4().hex[:8]
    # folder_name = f"{username}_{submission_id}"
    folder_name = f"{username}-{submission_id}"
    folder_path = os.path.join(CODE_ROOT, folder_name)
    os.makedirs(folder_path, exist_ok=True)
    with open(os.path.join(folder_path, "submission.py"), "w") as f:
        f.write(code)

    # 2. Define the executor pod. It mounts the SAME PersistentVolumeClaim as
    #    this API pod, but with subPath set — so /code inside the executor
    #    resolves to only this one folder, not the whole shared volume.
    pod_name = f"exec-{folder_name}"
    pod = client.V1Pod(
        metadata=client.V1ObjectMeta(name=pod_name, labels={"app": "code-executor-job"}),
        spec=client.V1PodSpec(
            restart_policy="Never",
            active_deadline_seconds=15,   # hard timeout — Kubernetes kills the pod if code runs longer than this
            containers=[client.V1Container(
                name="runner",
                image=EXECUTOR_IMAGE,
                command=["python", "/code/submission.py"],
                volume_mounts=[client.V1VolumeMount(
                    name="code", mount_path="/code", sub_path=folder_name,
                )],
                resources=client.V1ResourceRequirements(
                    requests={"cpu": "100m", "memory": "64Mi"},
                    limits={"cpu": "250m", "memory": "128Mi"},
                ),
            )],
            volumes=[client.V1Volume(
                name="code",
                persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(claim_name="user-code"),
            )],
        ),
    )

    # 3. Create it, wait for it to finish, grab its logs as the "output",
    #    then always delete it — successful or not, nothing lingers.
    k8s.create_namespaced_pod(namespace=NAMESPACE, body=pod)
    try:
        phase = _wait_for_completion(pod_name, timeout=20)
        logs = k8s.read_namespaced_pod_log(name=pod_name, namespace=NAMESPACE)
    except Exception as e:
        phase, logs = "Error", str(e)
    finally:
        k8s.delete_namespaced_pod(name=pod_name, namespace=NAMESPACE)

    return jsonify({"status": phase, "output": logs}), 200


def _wait_for_completion(pod_name, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        p = k8s.read_namespaced_pod(name=pod_name, namespace=NAMESPACE)
        if p.status.phase in ("Succeeded", "Failed"):
            return p.status.phase
        time.sleep(1)
    return "Timeout"


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)