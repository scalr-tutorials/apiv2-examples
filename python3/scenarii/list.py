# coding:utf-8
import json
import urllib.parse
import requests.exceptions


def execute(client, env_id):
    for path in [
        "/api/v1beta0/user/{0}/os/?family=ubuntu".format(env_id),
        "/api/v1beta0/user/{0}/role-categories/".format(env_id),
        "/api/v1beta0/user/{0}/roles/".format(env_id),
        "/api/v1beta0/user/{0}/images/".format(env_id)
    ]:
        print("\n\n\n")
        try:
            print("Accessing list endpoint: {0}".format(path))
            l = client.list(path)

            print("Found {0} records like:".format(len(l)))
            print(json.dumps(l[0], indent=4))
            print()

            # Remove the parameters if they exist, then compute the detail URL
            detail_url = "".join([getattr(urllib.parse.urlparse(path), k) for k in ["scheme", "netloc", "path"]])
            detail_url += str(l[-1]["id"])
            print("Accessing detail endpoint: {0}".format(detail_url))

            body = client.fetch(detail_url)
            print(json.dumps(body, indent=4))
        except requests.exceptions.HTTPError as e:
            print("ERROR!", e.response.status_code, e.response.text)
            continue
