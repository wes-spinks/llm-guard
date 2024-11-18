import flask
import json
import logging
import multiprocessing as mp
import os
import urllib.request
import uuid
from typing import Any, Optional
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from datetime import datetime
from flask import Flask, Response, jsonify, make_response, request, render_template
from flask_cors import CORS, cross_origin

APP_HOST = os.environ.get("APP_HOST", "0.0.0.0")
APP_PORT = os.environ.get("APP_PORT", "8443")

LOG_FMT = "[%(asctime)s] [%(process)d] [%(levelname)s] %(message)s"
LOG_DATE_FMT = "%Y-%m-%d %H:%M:%S %z"
logging.basicConfig(
    format=LOG_FMT,
    datefmt=LOG_DATE_FMT,
    stream=sys.stdout,
    level=logging.INFO,
)

app = Flask(__name__)
app.logger.setLevel(os.environ.get("LOGGING_LEVEL", "INFO"))
cors = CORS(app, resources={r"/*": {"origins": "*", "allow_headers": "*", "expose_headers": "*"}})


@app.route("/health", methods=["GET"])
def ready():
    """Simple health check to confirm app is responding

    Returns:
        str: literal "OK"
    """
    return "OK"


@app.route("/input", methods=["POST"])
@cross_origin(origin='*')
def scan_input():
    """Endpoint to perform guardrails scan on user INPUT prompt

    Arguments:
        prompt (dict): 'prompt' key with string value of user input

    Returns:
        dict: with status and sanitized_prompt keys
          status[str]:
            one of the following states: "success", "failed", "error", "exception"
          sanitized_prompt(optional)[str]:
            sanitized version of prompt, if applicable
          details(optional)[obj]:
            extra request/response information
    """
    import kitpg
    content = {"status": "error", "sanitized_prompt": ""}
    data = request.get_json()
    app.logger.debug(f"INPUT scanning:\n{data['prompt']}")
    try:
        scan = kitpg.input_guard(data["prompt"])
        if not scan["sanitized_prompt"]:
            content["details"] = "Error during scan."
            content["failed"] = scan["failed"]
            return content
        content["sanitized_prompt"] = scan["sanitized_prompt"]
        content["failed"] = scan["failed"]
        content["status"] = "success"
    except Exception as err:
        content["details"] = str(err)
        content["status"] = "exception"
    app.logger.info(f"""request: {data}; scan output: {content}""")
    return make_response(jsonify(content), 202)


@app.route("/output", methods=["POST"])
def scan_output():
    """Endpoint to perform guardrails scan on LLM OUTPUT prompt

    Arguments:
        prompt (dict): 'prompt' key with string value of user input

    Returns:
        dict: with status and sanitized_prompt keys
          status[str]:
            one of the following states: "success", "failed", "error", "exception"
          sanitized_prompt(optional)[str]:
            sanitized version of prompt, if applicable
          details(optional)[obj]:
            extra request/response information
    """
    content = {"status": "error", "sanitized_prompt": ""}
    data = request.get_json()
    app.logger.debug(f"OUTPUT scanning:\n{data['prompt']}")

    try:
        scan = kitpg.output_guard(data["prompt"])
        if not scan:
            content["details"] = "Error during scan."
            return content
        content["sanitized_prompt"] = scan[0]
        content["status"] = "success"
    except Exception as err:
        content["details"] = str(err)
        content["status"] = "exception"
    app.logger.info(f"""request: {data}; scan output: {content}""")
    return make_response(jsonify(content), 202)


if __name__ == "__main__":
    app.run(host=APP_HOST, port=APP_PORT, debug=True)
