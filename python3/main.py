#!/usr/bin/env python
#coding:utf-8
import json
import importlib
import logging

import requests
import requests.auth

from api.client import ScalrApiClient


def main(credentials_file, scenario, log_level=logging.INFO):
    # Setup credentials
    with open(credentials_file) as f:
        creds = json.load(f)
        api_url, api_key_id, api_key_secret, env_id = \
                [creds.get(k, "") for k in ["api_url", "api_key_id", "api_key_secret", "env_id"]]

    client = ScalrApiClient(api_url.rstrip("/"), api_key_id, api_key_secret)
    client.logger.setLevel(log_level)

    # Load scenario
    mod = importlib.import_module(".".join(["scenarii", scenario]))
    mod.execute(client, env_id)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("credentials", help="Path to credentials file")
    parser.add_argument("scenario", help="Name of the scenario to execute")
    parser.add_argument('--debug', action='store_true', default=False, help="Debug mode")

    ns = parser.parse_args()

    log_level = logging.INFO
    if ns.debug:
        log_level = logging.DEBUG

    main(ns.credentials, ns.scenario, log_level=log_level)
