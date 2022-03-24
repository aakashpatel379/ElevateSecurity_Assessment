from flask import Flask
import requests
import jsbeautifier
import json

app = Flask(__name__)
DEFAULT_URL = "https://incident-api.use1stag.elevatesecurity.io"
AUTH_USERNAME = "elevateinterviews"
AUTH_PASSWORD = "ElevateSecurityInterviews2021"


@app.route('/incidents')
def retrieve_incidents():
    r = requests.get(DEFAULT_URL + '/identities', auth=(AUTH_USERNAME, AUTH_PASSWORD))
    ip_dict = json.loads(r.text)
    emp_ip = {}
    for k, v in ip_dict.items():
        emp_ip[str(v)] = k

    incident_types = ['/denial', '/intrusion', '/executable', '/misuse', '/unauthorized', '/probing', '/other']
    med_incidents = []
    low_incidents = []
    high_incidents = []
    sev_incidents = []
    unidentified_incidents = []
    for type in incident_types:
        r = requests.get(DEFAULT_URL + "/incidents" + type, auth=(AUTH_USERNAME, AUTH_PASSWORD))
        res_data = json.loads(r.text)
        for item in res_data["results"]:
            res = {}
            if item["priority"] == "low":
                for source in item.keys():
                    if source in ["source_ip", "identifier", "ip", "machine_ip", "employee_id"]:
                        res["machine_ip"] = str(item[source])
                        break

                res["type"] = type[1:]
                res["priority"] = item["priority"]
                res["timestamp"] = item["timestamp"]
                low_incidents.append(res)

            if item["priority"] == "medium":
                for source in item.keys():
                    if source in ["source_ip", "identifier", "ip", "machine_ip", "employee_id"]:
                        res["machine_ip"] = str(item[source])
                        break
                res["type"] = type[1:]
                res["priority"] = item["priority"]
                res["timestamp"] = item["timestamp"]
                med_incidents.append(res)

            if item["priority"] == "high":
                for source in item.keys():
                    if source in ["source_ip", "identifier", "ip", "machine_ip", "employee_id"]:
                        res["machine_ip"] = str(item[source])
                        break

                res["type"] = type[1:]
                res["priority"] = item["priority"]
                res["timestamp"] = item["timestamp"]
                high_incidents.append(res)

            if item["priority"] == "severe":
                for source in item.keys():
                    if source in ["source_ip", "identifier", "ip", "machine_ip", "employee_id"]:
                        res["machine_ip"] = str(item[source])
                        break

                res["type"] = type[1:]
                res["priority"] = item["priority"]
                res["timestamp"] = item["timestamp"]
                sev_incidents.append(res)
    low_incidents = sorted(low_incidents, key=lambda d: d["timestamp"])
    med_incidents = sorted(med_incidents, key=lambda d: d["timestamp"])
    high_incidents = sorted(high_incidents, key=lambda d: d["timestamp"])
    sev_incidents = sorted(sev_incidents, key=lambda d: d["timestamp"])
    ans = {}
    print("Logging unidentified security incidents: ")
    for incident in low_incidents:
        if "." in incident["machine_ip"]:
            if incident["machine_ip"] in ip_dict:
                emp_id = ip_dict[incident["machine_ip"]]
            else:
                print(incident)
                unidentified_incidents.append(incident)
            if emp_id not in ans:
                incidents = [incident]
                ans[emp_id] = {"low": {"count": 1, "incidents": incidents}, "medium": {"count": 0, "incidents": []},
                               "high": {"count": 0, "incidents": []}, "severe": {"count": 0, "incidents": []}}

            else:
                ans[emp_id]["low"]["count"] += 1
                ans[emp_id]["low"]["incidents"].append(incident)
        else:
            emp_id = incident["machine_ip"]
            incident["machine_ip"] = emp_ip[emp_id]
            if emp_id not in ans:
                incidents = [incident]
                ans[emp_id] = {"low": {"count": 1, "incidents": incidents}, "medium": {"count": 0, "incidents": []},
                               "high": {"count": 0, "incidents": []}, "severe": {"count": 0, "incidents": []}}
            else:
                ans[emp_id]["low"]["count"] += 1
                ans[emp_id]["low"]["incidents"].append(incident)

    for incident in med_incidents:
        if "." in incident["machine_ip"]:
            if incident["machine_ip"] in ip_dict:
                emp_id = ip_dict[incident["machine_ip"]]
            else:
                print(incident)
                unidentified_incidents.append(incident)
            if emp_id not in ans:
                incidents = [incident]
                ans[emp_id] = {"low": {"count": 0, "incidents": []}, "medium": {"count": 1, "incidents": incidents},
                               "high": {"count": 0, "incidents": []}, "severe": {"count": 0, "incidents": []}}

            else:

                ans[emp_id]["medium"]["count"] += 1
                ans[emp_id]["medium"]["incidents"].append(incident)
        else:
            emp_id = incident["machine_ip"]
            incident["machine_ip"] = emp_ip[emp_id]
            if emp_id not in ans:
                incidents = [incident]
                ans[emp_id] = {"low": {"count": 0, "incidents": []}, "medium": {"count": 1, "incidents": incidents},
                               "high": {"count": 0, "incidents": []}, "severe": {"count": 0, "incidents": []}}
            else:

                ans[emp_id]["medium"]["count"] += 1
                ans[emp_id]["medium"]["incidents"].append(incident)

    for incident in high_incidents:
        if "." in incident["machine_ip"]:
            if incident["machine_ip"] in ip_dict:
                emp_id = ip_dict[incident["machine_ip"]]
            else:
                print(incident)
                unidentified_incidents.append(incident)
            if emp_id not in ans:
                incidents = [incident]
                ans[emp_id] = {"low": {"count": 0, "incidents": []}, "medium": {"count": 0, "incidents": []},
                               "high": {"count": 1, "incidents": incidents}, "severe": {"count": 0, "incidents": []}}

            else:
                ans[emp_id]["high"]["count"] += 1
                ans[emp_id]["high"]["incidents"].append(incident)
        else:
            emp_id = incident["machine_ip"]
            incident["machine_ip"] = emp_ip[emp_id]
            if emp_id not in ans:
                incidents = [incident]
                ans[emp_id] = {"low": {"count": 0, "incidents": []}, "medium": {"count": 0, "incidents": []},
                               "high": {"count": 1, "incidents": incidents}, "severe": {"count": 0, "incidents": []}}
            else:
                ans[emp_id]["high"]["count"] += 1
                ans[emp_id]["high"]["incidents"].append(incident)

    for incident in sev_incidents:
        if "." in incident["machine_ip"]:
            if incident["machine_ip"] in ip_dict:
                emp_id = ip_dict[incident["machine_ip"]]
            else:
                print(incident)
                unidentified_incidents.append(incident)
            if emp_id not in ans:
                incidents = [incident]
                ans[emp_id] = {"low": {"count": 0, "incidents": []}, "medium": {"count": 0, "incidents": []},
                               "high": {"count": 0, "incidents": []}, "severe": {"count": 1, "incidents": incidents}}

            else:
                ans[emp_id]["severe"]["count"] += 1
                ans[emp_id]["severe"]["incidents"].append(incident)
        else:
            emp_id = incident["machine_ip"]
            incident["machine_ip"] = emp_ip[emp_id]
            if emp_id not in ans:
                incidents = []
                incidents.append(incident)
                ans[emp_id] = {"low": {"count": 0, "incidents": []}, "medium": {"count": 0, "incidents": []},
                               "high": {"count": 0, "incidents": []}, "severe": {"count": 1, "incidents": incidents}}
            else:
                ans[emp_id]["severe"]["count"] += 1
                ans[emp_id]["severe"]["incidents"].append(incident)

    opts = jsbeautifier.default_options()
    opts.indent_size = 4
    return jsbeautifier.beautify(json.dumps(ans), opts)


if __name__ == '__main__':
    app.run(port=9000)
